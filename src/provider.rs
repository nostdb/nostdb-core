//! Talking to an out-of-process provider.
//!
//! A provider is a separate executable that retrieves bytes and metadata from somewhere the
//! Engine cannot reach on its own. This is the Engine's half of the conversation the
//! `provider_protocol_version` contract defines.
//!
//! # Why the transport is a trait
//!
//! Every test here runs against a scripted transport: no process is spawned, no pipe is
//! opened, and no network is touched. That is not a convenience for testing. A client that
//! could only be exercised by launching a real executable against a real host is one nobody
//! can verify in CI, and the product contract requires behavior on a *cached* snapshot
//! while the host is unreachable — a case a live test could not produce on demand.
//!
//! # What the Engine does not trust
//!
//! A provider holds a credential, talks to a network, and is the component most likely to
//! have been written by somebody else. So the Engine checks rather than accepts.
//!
//! - a `read` reply declares a length and exactly that many bytes are consumed. A stream
//!   that cannot supply them is closed rather than resynchronized, because a stream whose
//!   framing is wrong cannot be trusted to report that it is wrong;
//! - a `materialize` reply carries a digest, and the Engine computes its own over the bytes
//!   it received. The reply's digest is a claim to check, not an answer to record;
//! - a reply that does not answer the request that was sent is a protocol violation.

use serde_json::{Value, json};
use std::fmt;

/// The protocol version this build speaks.
pub const PROVIDER_PROTOCOL_VERSION: u32 = 1;

/// A provider role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Resolves, enumerates, and reads a source.
    Source,
    /// Resolves and materializes a published graph.
    GraphStore,
}

impl Role {
    /// The name the protocol uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::GraphStore => "graph_store",
        }
    }

    /// Reads a role from its protocol name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "source" => Some(Self::Source),
            "graph_store" => Some(Self::GraphStore),
            _ => None,
        }
    }
}

/// What a provider said about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    /// The provider's name.
    pub provider: String,
    /// Its own version, which is not the protocol's.
    pub provider_version: String,
    /// The roles it implements.
    pub roles: Vec<Role>,
}

impl Handshake {
    /// Reports whether this provider implements a role.
    #[must_use]
    pub fn implements(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

/// An immutable snapshot a locator resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The host's immutable identifier — for GitHub, a commit.
    pub snapshot: String,
    /// The locator, normalized. This is what the Engine stores.
    pub canonical_locator: String,
    /// Whether this came from a cache rather than from the host.
    pub cached: bool,
}

/// One entry a snapshot contains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The path within the snapshot.
    pub path: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// The host's own identifier for the content.
    ///
    /// Used to decide what to *avoid downloading*, never as a digest the Engine trusts.
    /// Conflating the two would let a host decide what the Engine believes about bytes it
    /// never checked.
    pub content_id: String,
}

/// Why a provider conversation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// The provider refused, with a code from the registry.
    Refused {
        /// The symbolic code, which is the signal.
        code: String,
        /// The provider's message, which carries no structure to branch on.
        message: String,
    },
    /// The provider spoke a version this build does not.
    VersionMismatch {
        /// What it reported.
        found: u64,
    },
    /// A reply was absent, malformed, or answered a different request.
    Protocol {
        /// What was wrong.
        reason: String,
    },
    /// The stream failed underneath the conversation.
    Transport {
        /// What was wrong.
        reason: String,
    },
    /// A materialized artifact did not match the digest the provider claimed.
    DigestMismatch {
        /// What the provider said.
        claimed: String,
        /// What the bytes actually are.
        computed: String,
    },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { code, message } => write!(formatter, "{code}: {message}"),
            Self::VersionMismatch { found } => write!(
                formatter,
                "the provider speaks protocol {found} and this build speaks \
                 {PROVIDER_PROTOCOL_VERSION}"
            ),
            Self::Protocol { reason } => {
                write!(formatter, "the provider broke the protocol: {reason}")
            }
            Self::Transport { reason } => write!(formatter, "the provider stream failed: {reason}"),
            Self::DigestMismatch { claimed, computed } => write!(
                formatter,
                "the artifact digests to {computed} and the provider claimed {claimed}"
            ),
        }
    }
}

impl std::error::Error for ProviderError {}

impl ProviderError {
    /// Reports whether this leaves a link declared rather than failing a build.
    ///
    /// The product contract requires an unavailable source to keep its declaration and
    /// yield reachable partial results. Only the provider's own unavailability code means
    /// that: a protocol violation is a defect in the provider, not a fact about the host,
    /// and treating the two alike would hide a broken provider behind a warning.
    #[must_use]
    pub fn leaves_link_declared(&self) -> bool {
        matches!(self, Self::Refused { code, .. } if code == "PROVIDER_SOURCE_UNAVAILABLE")
    }
}

/// A line-and-bytes stream to a provider.
///
/// Implemented over a child process's pipes in production, and over a script in every test.
pub trait Transport {
    /// Sends one request line.
    ///
    /// # Errors
    ///
    /// Returns a reason when the stream cannot be written.
    fn send(&mut self, line: &str) -> Result<(), String>;

    /// Receives one reply line, without its terminator.
    ///
    /// # Errors
    ///
    /// Returns a reason when the stream cannot be read or has ended.
    fn receive(&mut self) -> Result<String, String>;

    /// Receives exactly `length` bytes of content following a reply line.
    ///
    /// # Errors
    ///
    /// Returns a reason when fewer bytes are available.
    fn receive_exact(&mut self, length: usize) -> Result<Vec<u8>, String>;
}

/// The Engine's side of a provider conversation.
#[derive(Debug)]
pub struct ProviderClient<T: Transport> {
    transport: T,
    handshake: Option<Handshake>,
}

impl<T: Transport> ProviderClient<T> {
    /// Wraps a transport. Nothing is sent until [`ProviderClient::handshake`].
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            handshake: None,
        }
    }

    /// What the provider said about itself, once asked.
    #[must_use]
    pub const fn declared(&self) -> Option<&Handshake> {
        self.handshake.as_ref()
    }

    /// Agrees a version and learns what the provider implements.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::VersionMismatch`] when the provider speaks another version,
    /// and [`ProviderError::Protocol`] when the reply is not a handshake.
    pub fn handshake(&mut self) -> Result<&Handshake, ProviderError> {
        let reply = self.exchange(&json!({
            "provider_protocol_version": PROVIDER_PROTOCOL_VERSION,
            "request": "handshake",
        }))?;
        expect(&reply, "handshake")?;

        let roles = reply
            .get("roles")
            .and_then(Value::as_array)
            .ok_or_else(|| protocol("the handshake declares no roles"))?
            .iter()
            .filter_map(|value| value.as_str().and_then(Role::parse))
            .collect();
        self.handshake = Some(Handshake {
            provider: text(&reply, "provider")?,
            provider_version: text(&reply, "provider_version")?,
            roles,
        });
        self.handshake
            .as_ref()
            .ok_or_else(|| protocol("the handshake was not recorded"))
    }

    /// Resolves a locator to an immutable snapshot.
    ///
    /// `credential` is a **name**, never a secret. The Engine does not hold the secret, so
    /// it cannot be the component that writes one somewhere.
    ///
    /// # Errors
    ///
    /// Returns whatever the provider refused with, or a protocol failure.
    pub fn resolve(
        &mut self,
        locator: &str,
        credential: Option<&str>,
    ) -> Result<Snapshot, ProviderError> {
        self.require_handshake()?;
        let mut request = json!({
            "provider_protocol_version": PROVIDER_PROTOCOL_VERSION,
            "request": "resolve",
            "locator": locator,
        });
        if let Some(name) = credential {
            request["credential"] = json!({ "ref": name });
        }
        let reply = self.exchange(&request)?;
        expect(&reply, "resolve")?;
        Ok(Snapshot {
            snapshot: text(&reply, "snapshot")?,
            canonical_locator: text(&reply, "canonical_locator")?,
            // Absent is not "fresh". A provider that did not say must not be recorded as
            // having confirmed the snapshot with the host.
            cached: reply
                .get("cached")
                .and_then(Value::as_bool)
                .ok_or_else(|| protocol("the resolve reply does not say whether it was cached"))?,
        })
    }

    /// Lists what a snapshot contains.
    ///
    /// # Errors
    ///
    /// Returns whatever the provider refused with, or a protocol failure.
    pub fn enumerate(&mut self, snapshot: &str) -> Result<Vec<Entry>, ProviderError> {
        self.require_handshake()?;
        let reply = self.exchange(&json!({
            "provider_protocol_version": PROVIDER_PROTOCOL_VERSION,
            "request": "enumerate",
            "snapshot": snapshot,
        }))?;
        expect(&reply, "enumerate")?;
        reply
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| protocol("the enumerate reply carries no entries"))?
            .iter()
            .map(|entry| {
                Ok(Entry {
                    path: text(entry, "path")?,
                    bytes: entry
                        .get("bytes")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| protocol("an entry states no length"))?,
                    content_id: text(entry, "content_id")?,
                })
            })
            .collect()
    }

    /// Reads one entry's bytes.
    ///
    /// # Errors
    ///
    /// Returns whatever the provider refused with, or a protocol failure. A declared length
    /// the stream cannot supply is a framing failure, and the caller closes the stream
    /// rather than sending another request.
    pub fn read(&mut self, snapshot: &str, path: &str) -> Result<Vec<u8>, ProviderError> {
        self.require_handshake()?;
        let reply = self.exchange(&json!({
            "provider_protocol_version": PROVIDER_PROTOCOL_VERSION,
            "request": "read",
            "snapshot": snapshot,
            "path": path,
        }))?;
        expect(&reply, "read")?;
        self.content(&reply)
    }

    /// Materializes a read-only graph artifact, verifying it.
    ///
    /// The provider's digest is a claim. The Engine computes its own over the bytes it
    /// received and refuses a mismatch, because a provider is not trusted to have got this
    /// right — which is the whole reason a digest travels with the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::DigestMismatch`] when the bytes are not what was claimed,
    /// and otherwise whatever the provider refused with.
    pub fn materialize(&mut self, snapshot: &str) -> Result<Vec<u8>, ProviderError> {
        self.require_handshake()?;
        let reply = self.exchange(&json!({
            "provider_protocol_version": PROVIDER_PROTOCOL_VERSION,
            "request": "materialize",
            "snapshot": snapshot,
        }))?;
        expect(&reply, "materialize")?;

        let claimed = text(&reply, "content_digest")?;
        let content = self.content(&reply)?;
        let computed = crate::sync::digest_bytes(&content);
        if computed.as_str() != claimed {
            return Err(ProviderError::DigestMismatch {
                claimed,
                computed: computed.as_str().to_owned(),
            });
        }
        Ok(content)
    }

    /// Reads the content run a reply declared.
    fn content(&mut self, reply: &Value) -> Result<Vec<u8>, ProviderError> {
        let length = reply
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| protocol("the reply declares no length"))?;
        let length = usize::try_from(length)
            .map_err(|_| protocol("the reply declares more bytes than this build can hold"))?;
        self.transport
            .receive_exact(length)
            .map_err(|reason| ProviderError::Transport { reason })
    }

    fn require_handshake(&self) -> Result<(), ProviderError> {
        if self.handshake.is_some() {
            return Ok(());
        }
        // A request sent before a version is agreed has already guessed what the reply will
        // mean.
        Err(protocol("no handshake has been exchanged"))
    }

    /// Sends a request and reads one reply, turning a refusal into an error.
    fn exchange(&mut self, request: &Value) -> Result<Value, ProviderError> {
        self.transport
            .send(&request.to_string())
            .map_err(|reason| ProviderError::Transport { reason })?;
        let line = self
            .transport
            .receive()
            .map_err(|reason| ProviderError::Transport { reason })?;
        let reply: Value = serde_json::from_str(&line)
            .map_err(|error| protocol(&format!("the reply is not JSON: {error}")))?;

        match reply
            .get("provider_protocol_version")
            .and_then(Value::as_u64)
        {
            Some(found) if found == u64::from(PROVIDER_PROTOCOL_VERSION) => {}
            Some(found) => return Err(ProviderError::VersionMismatch { found }),
            None => return Err(protocol("the reply states no protocol version")),
        }

        if reply.get("reply").and_then(Value::as_str) == Some("error") {
            return Err(ProviderError::Refused {
                code: reply
                    .get("code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| protocol("a refusal carries no code"))?
                    .to_owned(),
                message: reply
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no message")
                    .to_owned(),
            });
        }
        Ok(reply)
    }
}

/// Reports whether a reply answers the request that was sent.
fn expect(reply: &Value, kind: &str) -> Result<(), ProviderError> {
    match reply.get("reply").and_then(Value::as_str) {
        Some(found) if found == kind => Ok(()),
        Some(found) => Err(protocol(&format!(
            "a `{kind}` request was answered with `{found}`"
        ))),
        None => Err(protocol("the reply names no kind")),
    }
}

fn text(value: &Value, key: &str) -> Result<String, ProviderError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| protocol(&format!("the reply states no `{key}`")))
}

fn protocol(reason: &str) -> ProviderError {
    ProviderError::Protocol {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that replays scripted replies and records what was sent.
    struct Scripted {
        replies: Vec<String>,
        content: Vec<Vec<u8>>,
        sent: Vec<String>,
    }

    impl Scripted {
        fn new(replies: &[&str]) -> Self {
            Self {
                replies: replies.iter().rev().map(|s| (*s).to_owned()).collect(),
                content: Vec::new(),
                sent: Vec::new(),
            }
        }

        fn with_content(mut self, content: &[&[u8]]) -> Self {
            self.content = content.iter().rev().map(|c| c.to_vec()).collect();
            self
        }
    }

    impl Transport for Scripted {
        fn send(&mut self, line: &str) -> Result<(), String> {
            self.sent.push(line.to_owned());
            Ok(())
        }

        fn receive(&mut self) -> Result<String, String> {
            self.replies
                .pop()
                .ok_or_else(|| "the stream ended".to_owned())
        }

        fn receive_exact(&mut self, length: usize) -> Result<Vec<u8>, String> {
            let found = self.content.pop().unwrap_or_default();
            if found.len() != length {
                return Err(format!(
                    "declared {length} bytes and supplied {}",
                    found.len()
                ));
            }
            Ok(found)
        }
    }

    const HANDSHAKE: &str = r#"{"provider_protocol_version":1,"reply":"handshake","provider":"github","provider_version":"1.0.0","roles":["source","graph_store"]}"#;

    fn shaken(replies: &[&str]) -> ProviderClient<Scripted> {
        let mut all = vec![HANDSHAKE];
        all.extend_from_slice(replies);
        let mut client = ProviderClient::new(Scripted::new(&all));
        client.handshake().expect("the handshake succeeds");
        client
    }

    #[test]
    fn a_handshake_reports_what_the_provider_implements() {
        let client = shaken(&[]);
        let declared = client.declared().expect("a handshake");
        assert_eq!(declared.provider, "github");
        assert!(declared.implements(Role::Source));
        assert!(declared.implements(Role::GraphStore));
    }

    #[test]
    fn no_request_may_precede_the_handshake() {
        // A request sent before a version is agreed has already guessed what the reply
        // will mean.
        let mut client = ProviderClient::new(Scripted::new(&[HANDSHAKE]));
        let refused = client.resolve("github://a/b/?ref=main", None).unwrap_err();
        assert!(
            matches!(refused, ProviderError::Protocol { .. }),
            "{refused}"
        );
        assert!(client.declared().is_none());
    }

    #[test]
    fn a_provider_speaking_another_version_is_refused() {
        let mut client = ProviderClient::new(Scripted::new(&[
            r#"{"provider_protocol_version":99,"reply":"handshake","provider":"x","provider_version":"1","roles":[]}"#,
        ]));
        assert_eq!(
            client.handshake().unwrap_err(),
            ProviderError::VersionMismatch { found: 99 }
        );
    }

    #[test]
    fn a_credential_travels_as_a_name_and_never_as_a_secret() {
        // The Engine cannot leak one it never held, which is the point of passing a
        // reference.
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"resolve","snapshot":"0f1e","canonical_locator":"github://a/b/?ref=main","cached":false}"#,
        ]);
        client
            .resolve("github://a/b/?ref=main", Some("github.work"))
            .expect("it resolves");
        let sent = client.transport.sent.last().expect("a request");
        assert!(sent.contains(r#""ref":"github.work""#), "{sent}");
        assert!(!sent.contains("token"), "{sent}");
    }

    #[test]
    fn a_resolve_that_does_not_say_whether_it_was_cached_is_refused() {
        // Absent is not "fresh". A provider that did not say must not be recorded as having
        // confirmed the snapshot with the host.
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"resolve","snapshot":"0f1e","canonical_locator":"github://a/b/?ref=main"}"#,
        ]);
        let refused = client.resolve("github://a/b/?ref=main", None).unwrap_err();
        assert!(
            matches!(refused, ProviderError::Protocol { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_cached_snapshot_is_reported_as_cached() {
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"resolve","snapshot":"0f1e","canonical_locator":"github://a/b/?ref=main","cached":true}"#,
        ]);
        let snapshot = client
            .resolve("github://a/b/?ref=main", None)
            .expect("resolves");
        assert!(snapshot.cached);
    }

    #[test]
    fn the_canonical_locator_is_what_the_engine_records() {
        // A locator is a link's identity, and two spellings of one identity is two links.
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"resolve","snapshot":"0f1e","canonical_locator":"github://example/payments/?ref=main","cached":false}"#,
        ]);
        let snapshot = client
            .resolve("https://github.com/Example/Payments/tree/main", None)
            .expect("resolves");
        assert_eq!(
            snapshot.canonical_locator,
            "github://example/payments/?ref=main"
        );
    }

    #[test]
    fn enumeration_reports_each_entry_with_the_hosts_own_identifier() {
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"enumerate","entries":[{"path":"src/main.rs","bytes":412,"content_id":"b1946ac9"}]}"#,
        ]);
        let entries = client.enumerate("0f1e").expect("enumerates");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "src/main.rs");
        assert_eq!(entries[0].content_id, "b1946ac9");
    }

    #[test]
    fn a_read_consumes_exactly_the_length_it_declared() {
        let mut client = ProviderClient::new(
            Scripted::new(&[
                HANDSHAKE,
                r#"{"provider_protocol_version":1,"reply":"read","bytes":5}"#,
            ])
            .with_content(&[b"hello"]),
        );
        client.handshake().expect("handshake");
        assert_eq!(client.read("0f1e", "a.txt").expect("reads"), b"hello");
    }

    #[test]
    fn a_read_whose_content_does_not_match_its_length_fails_the_stream() {
        // A stream whose framing is wrong cannot be trusted to report that it is wrong, so
        // this is a transport failure and the caller closes the stream.
        let mut client = ProviderClient::new(
            Scripted::new(&[
                HANDSHAKE,
                r#"{"provider_protocol_version":1,"reply":"read","bytes":99}"#,
            ])
            .with_content(&[b"short"]),
        );
        client.handshake().expect("handshake");
        let refused = client.read("0f1e", "a.txt").unwrap_err();
        assert!(
            matches!(refused, ProviderError::Transport { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_materialized_artifact_is_digested_by_the_engine_not_taken_on_trust() {
        let content = b"a graph artifact";
        let digest = crate::sync::digest_bytes(content);
        let reply = format!(
            r#"{{"provider_protocol_version":1,"reply":"materialize","bytes":{},"content_digest":"{}"}}"#,
            content.len(),
            digest.as_str()
        );
        let mut client =
            ProviderClient::new(Scripted::new(&[HANDSHAKE, &reply]).with_content(&[content]));
        client.handshake().expect("handshake");
        assert_eq!(client.materialize("0f1e").expect("materializes"), content);
    }

    #[test]
    fn an_artifact_that_is_not_what_was_claimed_is_refused() {
        // The provider's digest is a claim to check. A provider is not trusted to have got
        // this right, which is the whole reason the digest travels with the artifact.
        let reply = r#"{"provider_protocol_version":1,"reply":"materialize","bytes":5,"content_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let mut client =
            ProviderClient::new(Scripted::new(&[HANDSHAKE, reply]).with_content(&[b"hello"]));
        client.handshake().expect("handshake");
        assert!(matches!(
            client.materialize("0f1e").unwrap_err(),
            ProviderError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn an_unavailable_source_leaves_the_link_declared_and_a_broken_provider_does_not() {
        // The contract requires an unavailable source to keep its declaration. A protocol
        // violation is a defect in the provider rather than a fact about the host, and
        // treating the two alike would hide a broken provider behind a warning.
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"error","code":"PROVIDER_SOURCE_UNAVAILABLE","message":"the host did not answer"}"#,
        ]);
        let refused = client.resolve("github://a/b/?ref=main", None).unwrap_err();
        assert!(refused.leaves_link_declared());
        assert!(!protocol("anything").leaves_link_declared());

        let mut rejected = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"error","code":"PROVIDER_CREDENTIAL_REJECTED","message":"the host refused it"}"#,
        ]);
        let refused = rejected
            .resolve("github://a/b/?ref=main", None)
            .unwrap_err();
        assert!(
            !refused.leaves_link_declared(),
            "a rejected credential is not a source that happens to be down"
        );
    }

    #[test]
    fn a_reply_answering_a_different_request_is_a_protocol_violation() {
        let mut client =
            shaken(&[r#"{"provider_protocol_version":1,"reply":"enumerate","entries":[]}"#]);
        let refused = client.resolve("github://a/b/?ref=main", None).unwrap_err();
        assert!(
            matches!(refused, ProviderError::Protocol { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_refusal_carrying_no_code_is_a_protocol_violation() {
        // The code is the signal. A caller matching on message text would break the first
        // time the wording improved.
        let mut client = shaken(&[
            r#"{"provider_protocol_version":1,"reply":"error","message":"something went wrong"}"#,
        ]);
        let refused = client.resolve("github://a/b/?ref=main", None).unwrap_err();
        assert!(
            matches!(refused, ProviderError::Protocol { .. }),
            "{refused}"
        );
    }
}
