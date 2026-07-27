//! The transaction journal.
//!
//! Replacing one file atomically needs no journal: a staged write followed by a
//! rename is already all-or-nothing. The journal exists for the case a rename cannot
//! cover, which is a change spanning several files. Adding a link touches the
//! database, the settings mirror, and possibly the materialized `.nost`, and a crash
//! between those renames would leave them disagreeing.
//!
//! # Record framing
//!
//! Each record is a 12-byte header followed by its payload:
//!
//! ```text
//! offset size field
//! 0      4    record kind, u32 little-endian
//! 4      4    payload length, u32 little-endian
//! 8      4    CRC-32C over the kind, the length, and the payload
//! 12     ..   payload
//! ```
//!
//! # Torn tails
//!
//! A journal is read until the first record that cannot be trusted: a truncated
//! header, a truncated payload, or a checksum mismatch. That record and everything
//! after it are discarded. A crash during an append leaves exactly that shape, so
//! discarding the tail is recovery rather than data loss.
//!
//! # Idempotent replay
//!
//! Only actions between a `Begin` and its matching `Commit` are replayed. An
//! uncommitted tail is rolled back by discarding its staged files. Replaying a
//! committed transaction twice has the same effect as replaying it once, because each
//! action is expressed as a desired end state rather than a delta.

use crate::crc::crc32c;
use crate::generation::Generation;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const KIND_BEGIN: u32 = 1;
const KIND_PROMOTE: u32 = 2;
const KIND_REMOVE: u32 = 3;
const KIND_COMMIT: u32 = 4;

const RECORD_HEADER_LENGTH: usize = 12;

/// One journalled action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalRecord {
    /// Opens a transaction for a target generation.
    Begin {
        /// The generation this transaction will produce.
        generation: Generation,
    },
    /// Renames a staged file over its destination.
    Promote {
        /// The staged file.
        staged: String,
        /// The destination it replaces.
        destination: String,
    },
    /// Removes a file.
    Remove {
        /// The file to remove.
        path: String,
    },
    /// Closes a transaction. Everything before it is durable intent.
    Commit,
}

impl JournalRecord {
    fn kind(&self) -> u32 {
        match self {
            Self::Begin { .. } => KIND_BEGIN,
            Self::Promote { .. } => KIND_PROMOTE,
            Self::Remove { .. } => KIND_REMOVE,
            Self::Commit => KIND_COMMIT,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::Begin { generation } => {
                payload.extend_from_slice(&generation.get().to_le_bytes());
            }
            Self::Promote {
                staged,
                destination,
            } => {
                write_string(&mut payload, staged);
                write_string(&mut payload, destination);
            }
            Self::Remove { path } => write_string(&mut payload, path),
            Self::Commit => {}
        }
        payload
    }

    /// Encodes this record, framed and checksummed.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.payload();
        let kind = self.kind();
        let length = payload.len() as u32;

        let mut covered = Vec::with_capacity(8 + payload.len());
        covered.extend_from_slice(&kind.to_le_bytes());
        covered.extend_from_slice(&length.to_le_bytes());
        covered.extend_from_slice(&payload);

        let mut record = Vec::with_capacity(RECORD_HEADER_LENGTH + payload.len());
        record.extend_from_slice(&kind.to_le_bytes());
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(&crc32c(&covered).to_le_bytes());
        record.extend_from_slice(&payload);
        record
    }
}

fn write_string(buffer: &mut Vec<u8>, value: &str) {
    buffer.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buffer.extend_from_slice(value.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Option<u32> {
        let end = self.at.checked_add(4)?;
        let array: [u8; 4] = self.bytes.get(self.at..end)?.try_into().ok()?;
        self.at = end;
        Some(u32::from_le_bytes(array))
    }

    fn u64(&mut self) -> Option<u64> {
        let end = self.at.checked_add(8)?;
        let array: [u8; 8] = self.bytes.get(self.at..end)?.try_into().ok()?;
        self.at = end;
        Some(u64::from_le_bytes(array))
    }

    fn string(&mut self) -> Option<String> {
        let length = usize::try_from(self.u32()?).ok()?;
        let end = self.at.checked_add(length)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        String::from_utf8(slice.to_vec()).ok()
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

fn decode_payload(kind: u32, payload: &[u8]) -> Option<JournalRecord> {
    let mut cursor = Cursor {
        bytes: payload,
        at: 0,
    };
    let record = match kind {
        KIND_BEGIN => JournalRecord::Begin {
            generation: Generation::from_raw(cursor.u64()?),
        },
        KIND_PROMOTE => JournalRecord::Promote {
            staged: cursor.string()?,
            destination: cursor.string()?,
        },
        KIND_REMOVE => JournalRecord::Remove {
            path: cursor.string()?,
        },
        KIND_COMMIT => JournalRecord::Commit,
        _ => return None,
    };
    // A trailing byte means the payload does not match the kind, so the record is
    // not trustworthy even though its checksum passed.
    if cursor.done() { Some(record) } else { None }
}

/// What a journal says should happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// Actions from the last committed transaction, to be re-applied.
    pub committed: Vec<JournalRecord>,
    /// Staged files from an uncommitted tail, to be discarded.
    pub abandoned_staged: Vec<String>,
    /// Whether a trailing record was discarded as torn or unreadable.
    pub truncated: bool,
}

impl Recovery {
    /// The generation the last committed transaction produced, when there was one.
    #[must_use]
    pub fn committed_generation(&self) -> Option<Generation> {
        self.committed.iter().find_map(|record| match record {
            JournalRecord::Begin { generation } => Some(*generation),
            _ => None,
        })
    }
}

/// Reads a journal and decides what recovery requires.
///
/// Records are read until one cannot be trusted; that record and everything after it
/// are discarded, and [`Recovery::truncated`] reports it.
#[must_use]
pub fn replay(bytes: &[u8]) -> Recovery {
    let mut records: Vec<JournalRecord> = Vec::new();
    let mut at = 0_usize;
    let mut truncated = false;

    while at < bytes.len() {
        let Some(header) = bytes.get(at..at.saturating_add(RECORD_HEADER_LENGTH)) else {
            truncated = true;
            break;
        };
        let mut cursor = Cursor {
            bytes: header,
            at: 0,
        };
        let (Some(kind), Some(length), Some(stored_crc)) =
            (cursor.u32(), cursor.u32(), cursor.u32())
        else {
            truncated = true;
            break;
        };
        let Ok(length) = usize::try_from(length) else {
            truncated = true;
            break;
        };
        let payload_start = at + RECORD_HEADER_LENGTH;
        let Some(payload_end) = payload_start.checked_add(length) else {
            truncated = true;
            break;
        };
        let Some(payload) = bytes.get(payload_start..payload_end) else {
            truncated = true;
            break;
        };

        let mut covered = Vec::with_capacity(8 + payload.len());
        covered.extend_from_slice(&kind.to_le_bytes());
        covered.extend_from_slice(&(length as u32).to_le_bytes());
        covered.extend_from_slice(payload);
        if crc32c(&covered) != stored_crc {
            truncated = true;
            break;
        }

        let Some(record) = decode_payload(kind, payload) else {
            truncated = true;
            break;
        };
        records.push(record);
        at = payload_end;
    }

    // Split at the last Commit. Anything after it is an uncommitted tail.
    //
    // `committed` is the last committed transaction only, not every record before
    // that Commit. Earlier transactions are already durable, and re-applying them
    // would do redundant filesystem work whose staged files no longer exist.
    let last_commit = records
        .iter()
        .rposition(|record| matches!(record, JournalRecord::Commit));

    let (committed, tail) = match last_commit {
        Some(commit_index) => {
            let tail = records.split_off(commit_index + 1);
            let begin_index = records
                .iter()
                .rposition(|record| matches!(record, JournalRecord::Begin { .. }))
                .unwrap_or(0);
            (records.split_off(begin_index), tail)
        }
        None => (Vec::new(), records),
    };

    let abandoned_staged = tail
        .into_iter()
        .filter_map(|record| match record {
            JournalRecord::Promote { staged, .. } => Some(staged),
            _ => None,
        })
        .collect();

    Recovery {
        committed,
        abandoned_staged,
        truncated,
    }
}

/// Encodes a whole transaction: a `Begin`, the actions, then a `Commit`.
#[must_use]
pub fn encode_transaction(generation: Generation, actions: &[JournalRecord]) -> Vec<u8> {
    let mut bytes = JournalRecord::Begin { generation }.encode();
    for action in actions {
        bytes.extend_from_slice(&action.encode());
    }
    bytes.extend_from_slice(&JournalRecord::Commit.encode());
    bytes
}

/// Why a journal could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// A path was not valid UTF-8, so it cannot be journalled.
    ///
    /// The journal has to be readable by any implementation, so it stores paths as
    /// UTF-8 rather than as platform-specific bytes.
    NonUtf8Path,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Path => formatter.write_str("a journalled path must be valid UTF-8"),
        }
    }
}

impl std::error::Error for JournalError {}

/// A change spanning several files, staged and then promoted as one.
///
/// A single file needs no journal: a staged write followed by a rename is already
/// all-or-nothing. This exists for the case that is not, which is what adding a link is —
/// the declaration lives in the database, its operational mirror in the settings, and the
/// canonical `.nost` and the synchronization baseline both follow from the pair.
///
/// A crash is safe at every point. Before the journal is committed, nothing has moved and
/// the staged files are abandoned. After it is committed, every promotion is recorded and
/// replay finishes them; re-applying a rename that already happened is a no-op, which is
/// what makes replay idempotent.
#[derive(Debug)]
pub struct FileTransaction {
    journal_path: PathBuf,
    generation: Generation,
    actions: Vec<JournalRecord>,
    staged: Vec<PathBuf>,
}

impl FileTransaction {
    /// Opens a transaction whose journal lives at `journal_path`.
    #[must_use]
    pub fn begin(journal_path: PathBuf, generation: Generation) -> Self {
        Self {
            journal_path,
            generation,
            actions: Vec::new(),
            staged: Vec::new(),
        }
    }

    /// Writes `contents` to a staging file that will replace `destination` on commit.
    ///
    /// # Errors
    ///
    /// Returns whatever writing the staging file reports.
    pub fn stage(&mut self, destination: &Path, contents: &[u8]) -> io::Result<()> {
        let staged = staging_path(destination);
        fs::write(&staged, contents)?;
        sync_file(&staged);
        self.actions.push(JournalRecord::Promote {
            staged: staged.to_string_lossy().into_owned(),
            destination: destination.to_string_lossy().into_owned(),
        });
        self.staged.push(staged);
        Ok(())
    }

    /// Records that `path` is removed on commit.
    pub fn remove(&mut self, path: &Path) {
        self.actions.push(JournalRecord::Remove {
            path: path.to_string_lossy().into_owned(),
        });
    }

    /// Reports whether anything was staged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Commits: records the intent durably, then carries it out.
    ///
    /// # Errors
    ///
    /// Returns whatever writing the journal or promoting a file reports. A failure after
    /// the journal is durable leaves the transaction replayable rather than half done.
    pub fn commit(self) -> io::Result<()> {
        if self.actions.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.journal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = encode_transaction(self.generation, &self.actions);
        fs::write(&self.journal_path, &bytes)?;
        sync_file(&self.journal_path);

        apply(&self.actions)?;

        // The journal is removed last. Until it is gone the transaction is replayable,
        // and replaying a finished one changes nothing.
        let _ = fs::remove_file(&self.journal_path);
        Ok(())
    }

    /// Discards the transaction, removing whatever it staged.
    pub fn abandon(self) {
        for staged in &self.staged {
            let _ = fs::remove_file(staged);
        }
    }
}

/// Carries out one set of journalled actions.
///
/// Idempotent: promoting a file that was already promoted finds no staging file and does
/// nothing, and removing a file that is already gone does nothing.
fn apply(actions: &[JournalRecord]) -> io::Result<()> {
    for action in actions {
        match action {
            JournalRecord::Promote {
                staged,
                destination,
            } => {
                let staged = Path::new(staged);
                if staged.exists() {
                    fs::rename(staged, Path::new(destination))?;
                }
            }
            JournalRecord::Remove { path } => {
                let path = Path::new(path);
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
            JournalRecord::Begin { .. } | JournalRecord::Commit => {}
        }
    }
    Ok(())
}

/// Finishes or discards whatever a journal at `journal_path` describes.
///
/// Called before reading a project, so a crash mid-transaction is resolved rather than
/// observed. A journal with no commit record is discarded along with its staged files:
/// the intent was never made durable, so carrying it out would be inventing a decision.
///
/// # Errors
///
/// Returns whatever reading the journal or promoting a file reports.
pub fn recover_at(journal_path: &Path) -> io::Result<Recovery> {
    if !journal_path.is_file() {
        return Ok(Recovery {
            committed: Vec::new(),
            abandoned_staged: Vec::new(),
            truncated: false,
        });
    }
    let bytes = fs::read(journal_path)?;
    let recovery = replay(&bytes);

    apply(&recovery.committed)?;
    for staged in &recovery.abandoned_staged {
        let _ = fs::remove_file(Path::new(staged));
    }
    let _ = fs::remove_file(journal_path);
    Ok(recovery)
}

/// The staging sibling of a destination.
fn staging_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(".staged");
    destination.with_file_name(name)
}

/// Flushes a file to disk, best effort.
///
/// Not every platform and filesystem supports it, and treating that as a failure would
/// break commits on systems where the rename is already durable.
fn sync_file(path: &Path) {
    if let Ok(file) = fs::File::open(path) {
        let _ = file.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn promote(staged: &str, destination: &str) -> JournalRecord {
        JournalRecord::Promote {
            staged: staged.to_owned(),
            destination: destination.to_owned(),
        }
    }

    #[test]
    fn every_record_kind_round_trips() {
        let records = vec![
            JournalRecord::Begin {
                generation: Generation::from_raw(7),
            },
            promote("a.tmp", "a"),
            JournalRecord::Remove {
                path: "old".to_owned(),
            },
            JournalRecord::Commit,
        ];
        let mut bytes = Vec::new();
        for record in &records {
            bytes.extend_from_slice(&record.encode());
        }
        let recovery = replay(&bytes);
        assert!(!recovery.truncated);
        assert_eq!(recovery.committed, records);
        assert!(recovery.abandoned_staged.is_empty());
    }

    #[test]
    fn a_committed_transaction_is_recovered_with_its_generation() {
        let bytes = encode_transaction(
            Generation::from_raw(9),
            &[promote("root.nostdb.tmp", "root.nostdb")],
        );
        let recovery = replay(&bytes);
        assert_eq!(
            recovery.committed_generation(),
            Some(Generation::from_raw(9))
        );
        assert!(recovery.abandoned_staged.is_empty());
        assert!(!recovery.truncated);
    }

    #[test]
    fn replay_is_idempotent_over_the_same_bytes() {
        let bytes = encode_transaction(Generation::from_raw(3), &[promote("x.tmp", "x")]);
        assert_eq!(replay(&bytes), replay(&bytes));
    }

    #[test]
    fn an_uncommitted_tail_is_rolled_back_rather_than_applied() {
        let mut bytes = encode_transaction(Generation::from_raw(1), &[promote("a.tmp", "a")]);
        // A second transaction that never committed.
        bytes.extend_from_slice(
            &JournalRecord::Begin {
                generation: Generation::from_raw(2),
            }
            .encode(),
        );
        bytes.extend_from_slice(&promote("b.tmp", "b").encode());

        let recovery = replay(&bytes);
        assert_eq!(
            recovery.committed_generation(),
            Some(Generation::from_raw(1))
        );
        assert_eq!(recovery.abandoned_staged, vec!["b.tmp".to_owned()]);
        assert!(!recovery.truncated);
    }

    #[test]
    fn a_torn_tail_is_discarded_at_every_truncation_point() {
        let bytes = encode_transaction(Generation::from_raw(5), &[promote("a.tmp", "a")]);
        let full = replay(&bytes);
        assert!(!full.truncated);

        // Truncating anywhere inside the final Commit record must fall back to no
        // committed transaction, and must never panic.
        for cut in 1..bytes.len() {
            let recovery = replay(&bytes[..cut]);
            assert!(
                recovery.truncated || recovery.committed_generation().is_none(),
                "a cut at {cut} was neither reported as truncated nor left uncommitted"
            );
        }
    }

    #[test]
    fn a_corrupt_record_stops_replay_rather_than_being_trusted() {
        let mut bytes = encode_transaction(Generation::from_raw(4), &[promote("a.tmp", "a")]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let recovery = replay(&bytes);
        assert!(recovery.truncated);
        // The Commit record was the corrupt one, so nothing is committed.
        assert_eq!(recovery.committed_generation(), None);
    }

    #[test]
    fn a_payload_that_does_not_match_its_kind_is_rejected() {
        // A Commit record carries no payload. Give it one, with a valid checksum.
        let payload = b"unexpected";
        let kind = KIND_COMMIT;
        let length = payload.len() as u32;
        let mut covered = Vec::new();
        covered.extend_from_slice(&kind.to_le_bytes());
        covered.extend_from_slice(&length.to_le_bytes());
        covered.extend_from_slice(payload);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&crc32c(&covered).to_le_bytes());
        bytes.extend_from_slice(payload);

        let recovery = replay(&bytes);
        assert!(recovery.truncated);
        assert!(recovery.committed.is_empty());
    }

    #[test]
    fn an_unknown_record_kind_stops_replay() {
        let kind = 999_u32;
        let length = 0_u32;
        let mut covered = Vec::new();
        covered.extend_from_slice(&kind.to_le_bytes());
        covered.extend_from_slice(&length.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&crc32c(&covered).to_le_bytes());

        assert!(replay(&bytes).truncated);
    }

    #[test]
    fn an_empty_journal_recovers_to_nothing() {
        let recovery = replay(&[]);
        assert!(!recovery.truncated);
        assert!(recovery.committed.is_empty());
        assert!(recovery.abandoned_staged.is_empty());
        assert_eq!(recovery.committed_generation(), None);
    }

    #[test]
    fn the_last_committed_transaction_wins() {
        let mut bytes = encode_transaction(Generation::from_raw(1), &[promote("a.tmp", "a")]);
        bytes.extend_from_slice(&encode_transaction(
            Generation::from_raw(2),
            &[promote("b.tmp", "b")],
        ));
        let recovery = replay(&bytes);
        assert_eq!(
            recovery.committed_generation(),
            Some(Generation::from_raw(2))
        );
    }

    fn scratch(label: &str) -> PathBuf {
        let mut base = std::env::temp_dir();
        base.push(format!("nostdb-core-journal-{label}"));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("temporary directory");
        base
    }

    #[test]
    fn a_committed_transaction_moves_every_file_and_removes_its_journal() {
        let base = scratch("commit");
        let first = base.join("first");
        let second = base.join("second");
        let doomed = base.join("doomed");
        fs::write(&first, "old").unwrap();
        fs::write(&doomed, "goes away").unwrap();

        let journal_path = base.join("journal");
        let mut transaction = FileTransaction::begin(journal_path.clone(), Generation::from_raw(4));
        transaction.stage(&first, b"new").unwrap();
        transaction.stage(&second, b"created").unwrap();
        transaction.remove(&doomed);
        transaction.commit().unwrap();

        assert_eq!(fs::read_to_string(&first).unwrap(), "new");
        assert_eq!(fs::read_to_string(&second).unwrap(), "created");
        assert!(!doomed.exists());
        assert!(!journal_path.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replaying_a_finished_transaction_changes_nothing() {
        // Recovery cannot know how far the crash got, so it re-applies every recorded
        // action. That is only safe because applying one twice is the same as once.
        let base = scratch("idempotent");
        let destination = base.join("destination");
        fs::write(&destination, "old").unwrap();
        let journal_path = base.join("journal");

        let mut transaction = FileTransaction::begin(journal_path.clone(), Generation::from_raw(1));
        transaction.stage(&destination, b"new").unwrap();
        let actions = transaction.actions.clone();
        transaction.commit().unwrap();
        assert_eq!(fs::read_to_string(&destination).unwrap(), "new");

        fs::write(
            &journal_path,
            encode_transaction(Generation::from_raw(1), &actions),
        )
        .unwrap();
        let recovery = recover_at(&journal_path).unwrap();
        assert!(!recovery.truncated);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "new",
            "the destination is not clobbered by a rename with nothing left to move"
        );
        assert!(!journal_path.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn abandoning_removes_what_was_staged_and_promotes_nothing() {
        let base = scratch("abandon");
        let destination = base.join("destination");
        fs::write(&destination, "untouched").unwrap();
        let journal_path = base.join("journal");

        let mut transaction = FileTransaction::begin(journal_path.clone(), Generation::from_raw(2));
        transaction.stage(&destination, b"never arrives").unwrap();
        let staged = staging_path(&destination);
        assert!(staged.exists());
        transaction.abandon();

        assert!(!staged.exists());
        assert!(
            !journal_path.exists(),
            "no journal is written before commit"
        );
        assert_eq!(fs::read_to_string(&destination).unwrap(), "untouched");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn recovering_where_there_is_no_journal_does_nothing() {
        let base = scratch("absent");
        let recovery = recover_at(&base.join("journal")).unwrap();
        assert!(recovery.committed.is_empty());
        assert!(!recovery.truncated);
        let _ = fs::remove_dir_all(&base);
    }
}
