//! Retry budget: exponential backoff with an explicit ceiling.
//!
//! The policy is pure data plus one pure decision function, so the request loop
//! in [`crate::RestClient`] stays a thin shell and the arithmetic is testable —
//! including property tests over arbitrary delays and attempt counts.
//!
//! This crate never sleeps: the loop awaits a caller-supplied [`Sleeper`], so
//! pacing (and therefore cancellation) stays under the caller's control.
//!
//! ```
//! use std::time::Duration;
//! use sipgate_flow::RetryPolicy;
//!
//! let policy = RetryPolicy::default();
//! assert_eq!(policy.delay(1, None), Some(Duration::from_millis(250)));
//! assert_eq!(policy.delay(2, None), Some(Duration::from_millis(500)));
//! // Third attempt failed: the budget is spent.
//! assert_eq!(policy.delay(3, None), None);
//! ```

use std::time::Duration;

use crate::error::Error;

/// How often, and how long, the client retries transient failures.
///
/// The default is three attempts (two retries) with 250 ms doubling to an
/// 8 s ceiling, honouring `Retry-After`. Every wait is capped by
/// [`RetryPolicy::max_delay`], so a hostile or broken proxy cannot park the
/// caller for an unbounded time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Total attempts, including the first one. `0` behaves like `1`.
    pub max_attempts: u32,
    /// Delay after the first failed attempt; doubles per further attempt.
    pub base_delay: Duration,
    /// Upper bound for a single wait, applied to backoff and `Retry-After`.
    pub max_delay: Duration,
    /// Use the server's `Retry-After` when present instead of the backoff.
    pub use_retry_after: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            use_retry_after: true,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries (`max_attempts = 1`).
    ///
    /// ```
    /// use sipgate_flow::RetryPolicy;
    /// assert_eq!(RetryPolicy::none().delay(1, None), None);
    /// ```
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// A policy with `max_attempts` total attempts and the default delays.
    ///
    /// ```
    /// use sipgate_flow::RetryPolicy;
    /// assert_eq!(RetryPolicy::new(5).max_attempts, 5);
    /// ```
    #[must_use]
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            ..Self::default()
        }
    }

    /// Overrides the first backoff step.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().with_base_delay(Duration::from_secs(1));
    /// assert_eq!(policy.delay(1, None), Some(Duration::from_secs(1)));
    /// ```
    #[must_use]
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Overrides the ceiling for a single wait.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new(10).with_max_delay(Duration::from_secs(2));
    /// assert_eq!(policy.delay(9, None), Some(Duration::from_secs(2)));
    /// ```
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Ignores `Retry-After` and always uses exponential backoff.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().without_retry_after();
    /// assert_eq!(
    ///     policy.delay(1, Some(Duration::from_secs(30))),
    ///     Some(Duration::from_millis(250))
    /// );
    /// ```
    #[must_use]
    pub fn without_retry_after(mut self) -> Self {
        self.use_retry_after = false;
        self
    }

    /// The wait after `attempts_failed` failed attempts, or `None` when the
    /// budget is spent and the caller must surface the error.
    ///
    /// `attempts_failed` counts completed attempts: `1` means the first try
    /// just failed.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().with_max_delay(Duration::from_secs(3));
    /// // Retry-After is honoured but clamped to the ceiling.
    /// assert_eq!(
    ///     policy.delay(1, Some(Duration::from_secs(30))),
    ///     Some(Duration::from_secs(3))
    /// );
    /// ```
    #[must_use]
    pub fn delay(&self, attempts_failed: u32, retry_after: Option<Duration>) -> Option<Duration> {
        let budget = self.max_attempts.max(1);
        if attempts_failed >= budget {
            return None;
        }

        if self.use_retry_after {
            if let Some(hint) = retry_after {
                return Some(hint.min(self.max_delay));
            }
        }

        // 2^30 attempts is already far past any sane budget; shifting by more
        // would overflow, and `saturating_mul` keeps the value finite anyway.
        let exponent = attempts_failed.saturating_sub(1).min(30);
        let factor = 1_u32 << exponent;
        let backoff = self.base_delay.saturating_mul(factor);
        Some(backoff.min(self.max_delay))
    }
}

/// Paces retries. The client awaits this and never calls `sleep` itself, so a
/// cancellation token, a runtime shutdown or a `select!` arm can interrupt the
/// wait — and tests can assert the exact sequence of delays.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::{NoSleep, Sleeper};
///
/// # async fn demo() {
/// let sleeper = NoSleep;
/// sleeper.sleep(Duration::from_millis(10)).await;
/// # }
/// ```
pub trait Sleeper: Send + Sync {
    /// Waits for `delay`. Implementations should be cancellation safe: no work
    /// may happen after the caller drops the future.
    fn sleep(&self, delay: Duration) -> impl std::future::Future<Output = ()> + Send;
}

/// A sleeper that returns immediately. Suitable for tests and for callers that
/// pace elsewhere; it makes retries back-to-back, so pair it with
/// [`RetryPolicy::none`] in production unless something else throttles.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::{NoSleep, Sleeper};
///
/// # async fn demo() {
/// NoSleep.sleep(Duration::from_secs(1)).await; // returns at once
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&self, _delay: Duration) -> impl std::future::Future<Output = ()> + Send {
        std::future::ready(())
    }
}

/// Adapts any `Fn(Duration) -> Future` into a [`Sleeper`], so a caller can plug
/// in `tokio::time::sleep` — cancellation safe when awaited inside `select!` —
/// without this crate depending on a runtime.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::{FnSleeper, Sleeper};
///
/// # async fn demo() {
/// let sleeper = FnSleeper::new(|delay: Duration| std::future::ready(drop(delay)));
/// sleeper.sleep(Duration::from_millis(5)).await;
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FnSleeper<F> {
    sleep: F,
}

impl<F> FnSleeper<F> {
    /// Wraps `sleep`, which must return a future resolving after its delay.
    ///
    /// ```
    /// use sipgate_flow::FnSleeper;
    /// let _ = FnSleeper::new(|_d: std::time::Duration| std::future::ready(()));
    /// ```
    pub fn new(sleep: F) -> Self {
        Self { sleep }
    }
}

impl<F, Fut> Sleeper for FnSleeper<F>
where
    F: Fn(Duration) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = ()> + Send,
{
    fn sleep(&self, delay: Duration) -> impl std::future::Future<Output = ()> + Send {
        (self.sleep)(delay)
    }
}

/// Parses a `Retry-After` header value in its delta-seconds form.
///
/// The HTTP-date form is deliberately not converted here: it needs a clock,
/// and sipgate sends delta-seconds. An unparseable value returns `None` so the
/// caller falls back to exponential backoff instead of failing the request.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::parse_retry_after;
///
/// assert_eq!(parse_retry_after("3"), Some(Duration::from_secs(3)));
/// assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
/// assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
/// ```
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok().map(Duration::from_secs)
}

/// Reads `Retry-After` through any header lookup function, mapping a missing or
/// unparseable header to `None`.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::retry_after_from;
///
/// let headers = |name: &str| (name == "retry-after").then_some("4");
/// assert_eq!(retry_after_from(headers), Some(Duration::from_secs(4)));
/// ```
pub fn retry_after_from<'a>(header: impl Fn(&str) -> Option<&'a str>) -> Option<Duration> {
    header("retry-after").and_then(parse_retry_after)
}

/// Classifies a status code: 429 and 5xx are worth retrying, everything else —
/// including 401, which has its own refresh path — is terminal.
///
/// ```
/// use sipgate_flow::classify_status;
///
/// assert!(classify_status(429));
/// assert!(classify_status(503));
/// assert!(!classify_status(404));
/// assert!(!classify_status(401));
/// ```
#[must_use]
pub fn classify_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Truncates a response body for an error message, so a multi-megabyte error
/// page cannot be held in memory or written to a log.
pub(crate) fn truncate_body(body: &str) -> String {
    const LIMIT: usize = 512;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut end = LIMIT;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &body[..end])
}

/// Maps a status plus headers into a terminal or retryable [`Error::Api`].
pub(crate) fn api_error(status: u16, headers: &[(&str, &str)], body: &str) -> Error {
    let retry_after = retry_after_from(|name| {
        headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    });
    Error::Api {
        status,
        body: truncate_body(body),
        retry_after,
        retryable: classify_status(status),
    }
}
