//! Running a provider as a child process.
//!
//! [`crate::provider::ProviderClient`] speaks the protocol over a [`Transport`]. This is the
//! transport that reaches a real one: a child process, its standard input, and its standard
//! output.
//!
//! # Why the framing is written out by hand
//!
//! A reply is a line; the content after a `read` is a fixed run of bytes on the same stream.
//! A buffered line reader will happily consume part of that run while looking for a newline,
//! and the bytes it swallowed are gone. So one reader owns the stream for its whole life,
//! and both the line read and the exact-length read go through it.
//!
//! That is also why a length mismatch is fatal rather than recoverable. Once the reader has
//! consumed a wrong number of bytes it has no way to know where the next reply begins, and
//! guessing would turn a provider's bug into the Engine's corrupted data.

use crate::provider::Transport;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A provider running as a child process.
#[derive(Debug)]
pub struct ProviderProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl ProviderProcess {
    /// Starts `program` with `arguments`, wiring its standard input and output.
    ///
    /// Standard error is inherited rather than captured: a provider's diagnostics are for a
    /// person, and swallowing them into a buffer nothing reads would make a misbehaving
    /// provider silent.
    ///
    /// The argument vector is passed directly, never through a shell. A provider path comes
    /// from configuration, and configuration is read from a repository somebody else may
    /// have written.
    ///
    /// # Errors
    ///
    /// Returns a reason when the process cannot be started or its pipes cannot be taken.
    pub fn start(program: &std::path::Path, arguments: &[&str]) -> Result<Self, String> {
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("{} could not be started: {error}", program.display()))?;

        let input = child
            .stdin
            .take()
            .ok_or_else(|| "the provider has no standard input".to_owned())?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| "the provider has no standard output".to_owned())?;
        Ok(Self {
            child,
            input,
            output: BufReader::new(output),
        })
    }

    /// Ends the conversation and waits for the process.
    ///
    /// Closing standard input is how a provider is told to stop: it reads end-of-file and
    /// returns. Killing it first would lose whatever it was in the middle of writing, and
    /// there is no reason to when the protocol has an ending.
    ///
    /// # Errors
    ///
    /// Returns a reason when the process cannot be waited for.
    pub fn finish(mut self) -> Result<std::process::ExitStatus, String> {
        drop(self.input);
        self.child
            .wait()
            .map_err(|error| format!("the provider could not be waited for: {error}"))
    }
}

impl Transport for ProviderProcess {
    fn send(&mut self, line: &str) -> Result<(), String> {
        // Written and flushed together. A request sitting in a buffer is a deadlock: the
        // Engine waits for a reply to a request the provider has not been given.
        self.input
            .write_all(line.as_bytes())
            .and_then(|()| self.input.write_all(b"\n"))
            .and_then(|()| self.input.flush())
            .map_err(|error| format!("the provider stopped reading: {error}"))
    }

    fn receive(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let read = self
            .output
            .read_line(&mut line)
            .map_err(|error| format!("the provider's answer could not be read: {error}"))?;
        if read == 0 {
            // End of stream where a reply was due. A provider that exits instead of
            // answering is what the contract forbids, and saying so beats a timeout.
            return Err("the provider ended without answering".to_owned());
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn receive_exact(&mut self, length: usize) -> Result<Vec<u8>, String> {
        let mut content = vec![0_u8; length];
        self.output.read_exact(&mut content).map_err(|error| {
            format!("the provider declared {length} bytes and did not supply them: {error}")
        })?;
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ProviderClient, Role};

    const SHAKE: &str = r#"printf '{"provider_protocol_version":1,"reply":"handshake","provider":"github","provider_version":"1","roles":["source"]}\n'"#;
    const RESOLVED: &str = r#"printf '{"provider_protocol_version":1,"reply":"resolve","snapshot":"0f1e","canonical_locator":"github://a/b/?ref=main","cached":false}\n'"#;

    /// Writes a shell script that replays canned output, and returns its path.
    ///
    /// A real child process rather than a fake, because what is being tested is the framing
    /// across a pipe — which a fake transport cannot get wrong in the same way.
    /// A counter, so two scripts never share a path.
    ///
    /// The label alone was the path, in a directory every test and every concurrent run shares. Tests
    /// in one binary run in parallel, so one could write a script while another was executing it —
    /// which the operating system reports as `ETXTBSY`, "text file busy", and which passed locally
    /// for as long as the timing happened not to overlap. Each test also deleted the shared path when
    /// it finished, so a slower one could lose its program mid-run.
    ///
    /// The process id and this counter make the path unique per script rather than per test name.
    #[cfg(unix)]
    static SCRIPTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[cfg(unix)]
    fn scripted(label: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let unique = SCRIPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "nostdb-provider-{label}-{}-{unique}.sh",
            std::process::id()
        ));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
        path
    }

    #[cfg(unix)]
    fn client(label: &str, body: &str) -> (ProviderClient<ProviderProcess>, std::path::PathBuf) {
        let program = scripted(label, body);
        let process = ProviderProcess::start(&program, &[]).expect("it starts");
        (ProviderClient::new(process), program)
    }

    #[cfg(unix)]
    #[test]
    fn a_handshake_crosses_a_real_pipe() {
        let (mut client, program) = client("handshake", &format!("read line\n{SHAKE}"));
        let declared = client.handshake().expect("it answers").clone();
        assert_eq!(declared.provider, "github");
        assert!(declared.implements(Role::Source));
        let _ = std::fs::remove_file(&program);
    }

    #[cfg(unix)]
    #[test]
    fn content_after_a_reply_is_read_as_bytes_and_keeps_its_newlines() {
        // The case a buffered line reader gets wrong: it consumes part of the content run
        // looking for a newline, and the bytes it swallowed are gone. A file with newlines
        // in it is the ordinary case and exactly what would be truncated.
        let (mut client, program) = client(
            "read",
            &format!(
                "read line\n{SHAKE}\nread line\n{RESOLVED}\nread line\n{}\n{}",
                r#"printf '{"provider_protocol_version":1,"reply":"read","bytes":10}\n'"#,
                r#"printf 'one\ntwo\nx\n'"#
            ),
        );
        client.handshake().expect("handshake");
        client
            .resolve("github://a/b/?ref=main", None)
            .expect("resolve");
        assert_eq!(
            client.read("0f1e", "a.txt").expect("read"),
            b"one\ntwo\nx\n"
        );
        let _ = std::fs::remove_file(&program);
    }

    #[cfg(unix)]
    #[test]
    fn a_provider_that_exits_instead_of_answering_says_so_rather_than_hanging() {
        // The contract requires a refusal to be a reply. A provider that exits leaves the
        // Engine with nothing, and naming that beats waiting for a timeout.
        let (mut client, program) = client("silent", "exit 0");
        let refused = client.handshake().unwrap_err();
        let reported = refused.to_string();

        // Either message is correct, and which one appears is a race the operating system
        // decides: if the child is already gone when the request is written, the write fails
        // with a broken pipe; if it is still alive, the write succeeds and the read finds
        // end-of-file. This asserted only the second, and passed on a machine slow enough to
        // lose the race — until a CI runner won it.
        //
        // What the test is for is the property in its name: the conversation *ends*, with a
        // reason, rather than blocking. Pinning which of the two reasons appeared was pinning
        // the scheduler.
        assert!(
            reported.contains("ended without answering") || reported.contains("stopped reading"),
            "{reported}"
        );
        let _ = std::fs::remove_file(&program);
    }

    #[cfg(unix)]
    #[test]
    fn a_provider_that_declares_more_bytes_than_it_sends_fails_the_stream() {
        let (mut client, program) = client(
            "short",
            &format!(
                "read line\n{SHAKE}\nread line\n{RESOLVED}\nread line\n{}\n{}",
                r#"printf '{"provider_protocol_version":1,"reply":"read","bytes":100}\n'"#,
                r#"printf 'short'"#
            ),
        );
        client.handshake().expect("handshake");
        client
            .resolve("github://a/b/?ref=main", None)
            .expect("resolve");
        assert!(client.read("0f1e", "a.txt").is_err());
        let _ = std::fs::remove_file(&program);
    }

    #[test]
    fn a_program_that_does_not_exist_is_reported_rather_than_panicking() {
        let absent = std::env::temp_dir().join("nostdb-provider-that-does-not-exist");
        let error = ProviderProcess::start(&absent, &[]).unwrap_err();
        assert!(error.contains("could not be started"), "{error}");
    }
}
