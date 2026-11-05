//! Retry budget: exponential backoff with equal jitter and an explicit ceiling.
//!
//! The policy is pure data plus one decision function, so the request loop in
//! [`crate::RestClient`] stays a thin shell. Locally computed backoff uses equal
//! jitter in `[d/2, d]` to avoid fleet-wide lockstep; a server-provided
//! `Retry-After` is honoured exactly (after clamping) because it is already the
//! peer's pacing instruction. Both documented forms are accepted: delta-seconds
//! and HTTP-date. A present but unusable header fails closed to the caller's
//! ceiling instead of silently falling back to the shortest backoff step.
//!
//! This crate never sleeps: the loop awaits a caller-supplied [`Sleeper`], so
//! pacing (and therefore cancellation) stays under the caller's control.
//!
//! Every retry wait is clamped to at least [`MIN_RETRY_DELAY`], so a zero
//! `base_delay`, zero `max_delay` or zero `Retry-After` hint cannot turn the
//! loop into an unthrottled hammer.
//!
//! A maintained backoff crate is not used here because [`RetryPolicy`] and
//! [`Sleeper`] must stay runtime-free and source-compatible; the jitter uses
//! the standard library's cheap randomized hasher seed instead.
//!
//! ```
//! use std::time::Duration;
//! use sipgate_flow::RetryPolicy;
//!
//! let policy = RetryPolicy::default();
//! let delay = policy.delay(1, None).expect("first retry");
//! assert!(delay >= Duration::from_millis(125));
//! assert!(delay <= Duration::from_millis(250));
//! // Third attempt failed: the budget is spent.
//! assert_eq!(policy.delay(3, None), None);
//! ```

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, UNIX_EPOCH};

use httpdate::parse_http_date;

use crate::auth::{Clock, SystemClock};
use crate::error::Error;
use crate::transport::Method;

/// The smallest wait a [`RetryPolicy`] will produce.
///
/// A zero base delay, zero ceiling or zero `Retry-After` hint is clamped up to
/// this floor, so accepted retries are never back-to-back.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::{RetryPolicy, MIN_RETRY_DELAY};
///
/// let policy = RetryPolicy::default().with_max_delay(Duration::ZERO);
/// assert_eq!(policy.delay(1, Some(Duration::ZERO)), Some(MIN_RETRY_DELAY));
/// ```
pub const MIN_RETRY_DELAY: Duration = Duration::from_millis(1);

/// How often, and how long, the client retries transient failures.
///
/// The default is three attempts (two retries) with 250 ms doubling to an
/// 8 s ceiling, honouring `Retry-After`. Backoff steps are jittered uniformly
/// in `[d/2, d]`, where `d` is the uncapped step clamped to
/// [`RetryPolicy::max_delay`], so independent callers do not retry in lockstep.
/// Every wait is clamped to `MIN_RETRY_DELAY..=RetryPolicy::max_delay`, so a
/// hostile or broken proxy cannot park the caller for an unbounded time and a
/// zero delay cannot hammer the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Total attempts, including the first one. `0` behaves like `1`.
    pub max_attempts: u32,
    /// Delay after the first failed attempt; doubles per further attempt.
    ///
    /// Values below [`MIN_RETRY_DELAY`] are clamped up to the floor by
    /// [`RetryPolicy::with_base_delay`].
    pub base_delay: Duration,
    /// Upper bound for a single wait, applied to backoff and `Retry-After`.
    ///
    /// Values below [`MIN_RETRY_DELAY`] are clamped up to the floor by
    /// [`RetryPolicy::with_max_delay`].
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
    /// `0` behaves like `1`: the first attempt still happens and no retry is
    /// scheduled after it.
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

    /// Overrides the first backoff step before jitter.
    ///
    /// Values below [`MIN_RETRY_DELAY`] are clamped up to the floor, so a
    /// zero base delay cannot produce a back-to-back retry.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().with_base_delay(Duration::from_secs(1));
    /// let delay = policy.delay(1, None).expect("first retry");
    /// assert!(delay >= Duration::from_millis(500));
    /// assert!(delay <= Duration::from_secs(1));
    /// ```
    #[must_use]
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay.max(MIN_RETRY_DELAY);
        self
    }

    /// Overrides the ceiling for a single wait.
    ///
    /// Values below [`MIN_RETRY_DELAY`] are clamped up to the floor, so a zero
    /// ceiling cannot produce a back-to-back retry.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new(10).with_max_delay(Duration::from_secs(2));
    /// let delay = policy.delay(9, None).expect("within budget");
    /// assert!(delay >= Duration::from_secs(1));
    /// assert!(delay <= Duration::from_secs(2));
    /// ```
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay.max(MIN_RETRY_DELAY);
        self
    }

    /// Ignores `Retry-After` and always uses exponential backoff.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().without_retry_after();
    /// let delay = policy.delay(1, Some(Duration::from_secs(30))).expect("first retry");
    /// assert!(delay >= Duration::from_millis(125));
    /// assert!(delay <= Duration::from_millis(250));
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
    /// just failed. Local exponential backoff is jittered uniformly in
    /// `[d/2, d]` after applying the ceiling; `Retry-After` is returned exactly
    /// after applying the ceiling. Every returned wait is clamped to
    /// [`MIN_RETRY_DELAY`]..=effective ceiling, where the effective ceiling is
    /// `max_delay.max(MIN_RETRY_DELAY)`.
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
                return Some(clamp_delay(hint, self.max_delay));
            }
        }

        // 2^30 attempts is already far past any sane budget; shifting by more
        // would overflow, and `saturating_mul` keeps the value finite anyway.
        let exponent = attempts_failed.saturating_sub(1).min(30);
        let factor = 1_u32 << exponent;
        let backoff = self.base_delay.saturating_mul(factor);
        Some(clamp_delay(
            equal_jitter(backoff, self.max_delay),
            self.max_delay,
        ))
    }
}

fn clamp_delay(delay: Duration, max_delay: Duration) -> Duration {
    delay.clamp(MIN_RETRY_DELAY, max_delay.max(MIN_RETRY_DELAY))
}

fn equal_jitter(backoff: Duration, max_delay: Duration) -> Duration {
    let capped = backoff.min(max_delay);
    let lower = capped / 2;
    let span = capped.as_nanos() - lower.as_nanos();
    if span == 0 {
        return capped;
    }

    let offset = random_u128() % (span + 1);
    duration_from_nanos(lower.as_nanos() + offset)
}

fn random_u128() -> u128 {
    let high = RandomState::new().build_hasher().finish();
    let low = RandomState::new().build_hasher().finish();
    (u128::from(high) << 64) | u128::from(low)
}

fn duration_from_nanos(nanos: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let seconds = nanos / NANOS_PER_SECOND;
    let subsecond = nanos % NANOS_PER_SECOND;
    let seconds = u64::try_from(seconds).unwrap_or(u64::MAX);
    let subsecond = u32::try_from(subsecond).unwrap_or(999_999_999);
    Duration::new(seconds, subsecond)
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

/// Parses a `Retry-After` header value in either documented form.
///
/// Delta-seconds are returned directly. HTTP-date values are converted with
/// [`SystemClock`], saturating at zero when the date is in the past. A value
/// this parser cannot read returns `None`; [`retry_after_from`] turns a present
/// but unreadable header into a maximal hint so a retry loop fails closed.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::parse_retry_after;
///
/// assert_eq!(parse_retry_after("3"), Some(Duration::from_secs(3)));
/// assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
/// assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), Some(Duration::ZERO));
/// ```
#[must_use]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    parse_retry_after_with_clock(value, &SystemClock)
}

fn parse_retry_after_with_clock<C: Clock>(value: &str, clock: &C) -> Option<Duration> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        // A value above `u64::MAX` is absurd but present. Keep it as a
        // maximal hint; `parse_retry_after` preserves the value and callers
        // clamp it to their own ceiling.
        return Some(
            trimmed
                .parse::<u64>()
                .map_or(Duration::MAX, Duration::from_secs),
        );
    }

    let deadline = parse_http_date(trimmed).ok()?;
    let now = UNIX_EPOCH.checked_add(clock.now().ok()?)?;
    Some(deadline.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Reads `Retry-After` through any header lookup function, failing closed when
/// the header is present but unusable.
///
/// A missing header yields `None`, so the caller's exponential backoff applies.
/// A present but unreadable header yields [`Duration::MAX`], which the retry
/// policy and error constructors clamp to their configured ceilings: a server
/// asking for pacing is never retried sooner because its hint was malformed.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::retry_after_from;
///
/// let headers = |name: &str| (name == "retry-after").then_some("4");
/// assert_eq!(retry_after_from(headers), Some(Duration::from_secs(4)));
/// assert_eq!(retry_after_from(|_| None), None);
/// assert_eq!(retry_after_from(|_| Some("not a date")), Some(Duration::MAX));
/// ```
pub fn retry_after_from<'a>(header: impl Fn(&str) -> Option<&'a str>) -> Option<Duration> {
    retry_after_from_with_clock(header, &SystemClock)
}

/// Reads `Retry-After` with an explicit clock for the HTTP-date form.
///
/// This is the clock-injectable form of [`retry_after_from`], useful when a
/// caller already owns a deterministic or custom [`Clock`].
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::{retry_after_from_with_clock, Clock, Result};
///
/// struct Fixed;
/// impl Clock for Fixed {
///     fn now(&self) -> Result<Duration> {
///         Ok(Duration::from_secs(1_700_000_000))
///     }
/// }
///
/// let headers = |name: &str| {
///     name.eq_ignore_ascii_case("retry-after")
///         .then_some("Tue, 14 Nov 2023 22:15:20 GMT")
/// };
/// assert_eq!(
///     retry_after_from_with_clock(headers, &Fixed),
///     Some(Duration::from_secs(120))
/// );
/// ```
pub fn retry_after_from_with_clock<'a, C: Clock>(
    header: impl Fn(&str) -> Option<&'a str>,
    clock: &C,
) -> Option<Duration> {
    let value = header("retry-after")?;
    Some(parse_retry_after_with_clock(value, clock).unwrap_or(Duration::MAX))
}

/// What a failed attempt means for a retry loop.
///
/// Three outcomes, not two, because a status alone cannot tell whether the
/// server acted on the request. `POST /v2/sessions/sms` answering `502` may
/// have sent the SMS with only the response lost, and sipgate documents no
/// idempotency key to make a repeat harmless. Interval between attempts: see
/// [`RetryPolicy::delay`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetryOutcome {
    /// Nothing happened yet (`408`, `425`, `429`), or the method is idempotent
    /// so repeating it cannot change the outcome: retry after the backoff.
    Retry,
    /// The request may have been executed and the method is not idempotent.
    /// Never retried automatically — the caller reconciles it.
    Ambiguous,
    /// Final answer: report it.
    Terminal,
}

/// Classifies `status` for a request with `method`.
///
/// `408`, `425` and `429` are emitted before the server processes anything, so
/// they are safe to repeat for every method. `501` and `505` are permanent
/// answers that do not depend on the request having been applied at all.
/// Other `5xx` responses mean the server may have read the request: on
/// `GET`/`PUT`/`DELETE` repeating them is harmless, on `POST` they are a
/// possible duplicate.
///
/// ```
/// use sipgate_flow::{classify, Method, RetryOutcome};
///
/// assert_eq!(classify(Method::Post, 429), RetryOutcome::Retry);
/// assert_eq!(classify(Method::Post, 408), RetryOutcome::Retry);
/// assert_eq!(classify(Method::Post, 503), RetryOutcome::Ambiguous);
/// assert_eq!(classify(Method::Post, 501), RetryOutcome::Terminal);
/// assert_eq!(classify(Method::Get, 503), RetryOutcome::Retry);
/// assert_eq!(classify(Method::Get, 505), RetryOutcome::Terminal);
/// assert_eq!(classify(Method::Delete, 500), RetryOutcome::Retry);
/// assert_eq!(classify(Method::Post, 400), RetryOutcome::Terminal);
/// assert_eq!(classify(Method::Get, 401), RetryOutcome::Terminal);
/// ```
#[must_use]
pub fn classify(method: Method, status: u16) -> RetryOutcome {
    let not_processed = matches!(status, 408 | 425 | 429);
    let permanent_server_error = matches!(status, 501 | 505);
    let server_error = (500..600).contains(&status);
    if not_processed || (server_error && !permanent_server_error && method.is_idempotent()) {
        RetryOutcome::Retry
    } else if server_error && !permanent_server_error {
        RetryOutcome::Ambiguous
    } else {
        RetryOutcome::Terminal
    }
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

/// Maps a status, its headers and the request method into the matching error:
/// terminal, retryable, or [`Error::Ambiguous`] when a non-idempotent request
/// may already have been executed.
pub(crate) fn api_error(
    method: Method,
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> Error {
    let retry_after = retry_after_from(|name| {
        headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    });
    let truncated = truncate_body(body);
    match classify(method, status) {
        RetryOutcome::Retry | RetryOutcome::Terminal => {
            Error::api(method, status, truncated, retry_after)
        }
        RetryOutcome::Ambiguous => Error::ambiguous_with_response(
            Some(status),
            format!(
                "api error {status} after a {} request may already have been applied: {truncated}",
                method.as_str()
            ),
            body,
            headers.iter().copied(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, RetryOutcome};
    use crate::transport::Method;

    #[test]
    fn classify_pins_the_refined_status_table() {
        assert_eq!(classify(Method::Post, 400), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Post, 402), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Post, 408), RetryOutcome::Retry);
        assert_eq!(classify(Method::Post, 425), RetryOutcome::Retry);
        assert_eq!(classify(Method::Post, 429), RetryOutcome::Retry);
        assert_eq!(classify(Method::Post, 500), RetryOutcome::Ambiguous);
        assert_eq!(classify(Method::Post, 501), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Post, 505), RetryOutcome::Terminal);

        assert_eq!(classify(Method::Get, 400), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Get, 402), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Get, 408), RetryOutcome::Retry);
        assert_eq!(classify(Method::Get, 425), RetryOutcome::Retry);
        assert_eq!(classify(Method::Get, 429), RetryOutcome::Retry);
        assert_eq!(classify(Method::Get, 500), RetryOutcome::Retry);
        assert_eq!(classify(Method::Get, 501), RetryOutcome::Terminal);
        assert_eq!(classify(Method::Get, 505), RetryOutcome::Terminal);
    }
}
