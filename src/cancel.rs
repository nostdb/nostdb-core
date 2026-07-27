//! Cooperative cancellation for a running query.
//!
//! The Engine runs a query to completion unless something tells it to stop. `nostdb-server`'s
//! protocol contract requires a configurable query timeout, and root `docs/PRD.md` section 30.6
//! lists timeouts among the Server's acceptance criteria, so the Engine has to offer a way to ask.
//!
//! # Cooperative, and where it is observed
//!
//! Nothing here interrupts anything. Execution *asks* whether it should stop, at boundaries where
//! stopping is safe and cheap to check:
//!
//! - between the parts of a `UNION`;
//! - between the clauses of a part;
//! - between the input rows of a `MATCH`.
//!
//! A single Engine operation that does not yield between those points is not interruptible. A
//! pattern expansion that produces an enormous cartesian product from **one** input row runs to
//! completion, and a caller waits for it. Stating the granularity is the honest thing to do: a
//! deadline that silently failed to apply in the worst case would be worse than none, because a
//! caller would stop watching for the case it does not cover.
//!
//! # Why a trait rather than a deadline
//!
//! A wall-clock deadline is one reason to stop and not the only one. A client disconnecting, an AI
//! token budget running out in Stage 10, and an operator asking a daemon to shut down are all the
//! same question asked by different callers, so the Engine takes the question rather than one
//! answer to it.

use std::time::{Duration, Instant};

/// Something a running query asks whether it should stop.
///
/// Implementations must be cheap. This is called at every boundary listed in the module
/// documentation, so an implementation that acquires a lock or reads a file would cost more than
/// the work it is guarding.
pub trait ShouldStop {
    /// Whether the query should stop now.
    fn should_stop(&self) -> bool;

    /// Why it stopped, for the diagnostic's message.
    ///
    /// The default names no reason beyond cancellation, which is right for a caller that simply
    /// asked. A deadline overrides it to say how long was allowed.
    fn reason(&self) -> String {
        "the query was cancelled".to_owned()
    }
}

/// Never stops.
///
/// The default for every caller that has no deadline, so the existing entry points keep their
/// behavior exactly.
#[derive(Debug, Clone, Copy, Default)]
pub struct Never;

impl ShouldStop for Never {
    fn should_stop(&self) -> bool {
        false
    }
}

/// Stops once a wall-clock instant has passed.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    until: Instant,
    allowed: Duration,
}

impl Deadline {
    /// A deadline `allowed` from now.
    #[must_use]
    pub fn after(allowed: Duration) -> Self {
        Self {
            until: Instant::now() + allowed,
            allowed,
        }
    }

    /// How long this deadline allows in total.
    #[must_use]
    pub const fn allowed(&self) -> Duration {
        self.allowed
    }
}

impl ShouldStop for Deadline {
    fn should_stop(&self) -> bool {
        Instant::now() >= self.until
    }

    fn reason(&self) -> String {
        format!(
            "the query exceeded its {} millisecond timeout",
            self.allowed.as_millis()
        )
    }
}

/// Stops when a flag is set.
///
/// The shape a daemon uses when the reason is a client disconnecting or a shutdown, rather than
/// time passing.
#[derive(Debug, Default)]
pub struct Flag(std::sync::atomic::AtomicBool);

impl Flag {
    /// A flag that is not yet set.
    #[must_use]
    pub const fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(false))
    }

    /// Asks every query watching this flag to stop.
    pub fn stop(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl ShouldStop for Flag {
    fn should_stop(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::{Deadline, Flag, Never, ShouldStop};
    use std::time::Duration;

    #[test]
    fn never_does_not_stop() {
        assert!(!Never.should_stop());
    }

    #[test]
    fn a_deadline_already_past_stops_immediately() {
        let deadline = Deadline::after(Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(2));
        assert!(deadline.should_stop());
        assert!(
            deadline.reason().contains("timeout"),
            "the reason must name the limit: {}",
            deadline.reason()
        );
    }

    #[test]
    fn a_deadline_in_the_future_does_not_stop_yet() {
        assert!(!Deadline::after(Duration::from_secs(3600)).should_stop());
    }

    #[test]
    fn a_flag_stops_only_once_set() {
        let flag = Flag::new();
        assert!(!flag.should_stop());
        flag.stop();
        assert!(flag.should_stop());
    }
}

#[cfg(test)]
mod execution_tests {
    use super::{Deadline, Flag, Never, ShouldStop};
    use crate::cypher::parse;
    use crate::diagnostic::DiagnosticCode;
    use crate::encoding::Graph;
    use crate::execute::{DatabaseContext, Parameters, execute_cancellable};
    use std::time::Duration;

    /// A token that stops after being asked `after` times.
    ///
    /// A wall-clock deadline would make this test depend on how fast the machine is. Counting the
    /// asks instead proves the same thing — that execution observes the token — without a sleep.
    struct StopsAfter {
        asks: std::cell::Cell<u32>,
        after: u32,
    }

    impl ShouldStop for StopsAfter {
        fn should_stop(&self) -> bool {
            let asks = self.asks.get() + 1;
            self.asks.set(asks);
            asks > self.after
        }

        fn reason(&self) -> String {
            "the test asked it to stop".to_owned()
        }
    }

    fn context() -> DatabaseContext {
        DatabaseContext {
            generation: None,
            source: None,
        }
    }

    #[test]
    fn a_query_runs_to_completion_when_nothing_asks_it_to_stop() {
        let mut graph = Graph::default();
        let query = parse("CREATE (:Service {name: 'a'})").expect("parsed");
        let result =
            execute_cancellable(&query, &mut graph, &Parameters::new(), &context(), &Never)
                .expect("completed");
        assert_eq!(result.writes.nodes_created, 1);
    }

    #[test]
    fn a_query_stops_with_its_own_code_when_asked() {
        let mut graph = Graph::default();
        let query = parse("MATCH (n) RETURN n").expect("parsed");
        let token = StopsAfter {
            asks: std::cell::Cell::new(0),
            after: 0,
        };
        let error = execute_cancellable(&query, &mut graph, &Parameters::new(), &context(), &token)
            .expect_err("stopped");
        assert_eq!(error.code, DiagnosticCode::QueryCancelled);
        assert!(
            error.message.contains("asked it to stop"),
            "the token's own reason must reach the caller: {}",
            error.message
        );
    }

    #[test]
    fn the_token_is_observed_more_than_once_per_query() {
        // Checking only at the very start would satisfy the test above and stop nothing that had
        // already begun. This proves the check happens at more than one boundary.
        let mut graph = Graph::default();
        let query = parse("MATCH (n) RETURN n").expect("parsed");
        let token = StopsAfter {
            asks: std::cell::Cell::new(0),
            after: u32::MAX,
        };
        let _ = execute_cancellable(&query, &mut graph, &Parameters::new(), &context(), &token);
        assert!(
            token.asks.get() > 1,
            "execution asked once, so a query already running could never be stopped"
        );
    }

    #[test]
    fn a_deadline_that_has_passed_stops_a_query() {
        let mut graph = Graph::default();
        let query = parse("MATCH (n) RETURN n").expect("parsed");
        let deadline = Deadline::after(Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(2));
        let error = execute_cancellable(
            &query,
            &mut graph,
            &Parameters::new(),
            &context(),
            &deadline,
        )
        .expect_err("stopped");
        assert_eq!(error.code, DiagnosticCode::QueryCancelled);
        assert!(
            error.message.contains("timeout"),
            "a deadline must say which limit stopped it: {}",
            error.message
        );
    }

    #[test]
    fn a_flag_set_before_the_query_stops_it() {
        let mut graph = Graph::default();
        let query = parse("MATCH (n) RETURN n").expect("parsed");
        let flag = Flag::new();
        flag.stop();
        let error = execute_cancellable(&query, &mut graph, &Parameters::new(), &context(), &flag)
            .expect_err("stopped");
        assert_eq!(error.code, DiagnosticCode::QueryCancelled);
    }
}
