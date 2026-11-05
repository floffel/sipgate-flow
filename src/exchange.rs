//! The authenticated request exchange shared by both clients.
//!
//! One rule lives here and only here: a 401 means the cached credential is
//! stale, so the token that was actually used is refreshed single-flight and
//! the request is retried exactly once. A second 401 is terminal — retrying it
//! would burn rate limit for nothing.
//!
//! The caller's per-request timeout is a budget for the whole exchange, not a
//! fresh allowance for each leg: a deadline is taken once at entry, every
//! attempt is given only what remains of it, and the single resend waits
//! through the caller's [`RetryPolicy`] (and [`Sleeper`]). The pause is clamped
//! so it cannot sleep past the deadline either, which is what keeps the 401
//! path inside the budget the caller set.
//!
//! The header the credential goes out with comes from
//! [`Token::security`](crate::auth::Token::security), not from this module: a
//! PAT is `Basic id:token`, an access token is `Bearer`, and neither should be
//! spelled out twice.

use serde_json::Value;
use std::time::{Duration, Instant};
use url::Url;

use crate::auth::TokenSource;
use crate::error::{Error, Result};
use crate::retry::{retry_after_from, RetryPolicy, Sleeper};
use crate::transport::{Method, Request, Response, Security, Transport};

/// The caller's budget and pacing for one exchange.
///
/// Bundled so the request shape stays a handful of positional arguments;
/// `timeout` is a total budget shared by both attempts, while `retry`/`sleeper`
/// pace the single resend.
pub(crate) struct Pacing<'a, S> {
    /// Total per-request budget, or `None` for the transport default.
    pub timeout: Option<Duration>,
    /// Policy the resend obeys; [`RetryPolicy::none`] vetoes the pause.
    pub retry: &'a RetryPolicy,
    /// Await the pause on this, never on a runtime the crate owns.
    pub sleeper: &'a S,
}

#[derive(Clone, Copy)]
pub(crate) struct Target<'a> {
    pub base_url: &'a str,
    pub allow_http_base_url: bool,
    pub path: &'a str,
}

/// Sends `method path` with the credential's scheme, refreshing once on 401.
///
/// `base_url` must be an absolute `https://` URL. `path` must start with a
/// single `/` and must not contain `//`, `..`, `@`, CR or LF; the joined URL is
/// checked again before the credential is attached.
///
/// `pacing.timeout` is the total budget for this exchange: both attempts and
/// the pause between them draw from the same deadline, so a 401 can never take
/// two full timeouts plus the token fetch. The single resend is paced through
/// `pacing.retry` and awaited on `pacing.sleeper`, so it obeys the same ceiling
/// as every other retry; a policy that vetoes the retry (such as
/// [`RetryPolicy::none`]) leaves the resend immediate.
pub(crate) async fn authorized<T, A, S>(
    transport: &T,
    auth: &A,
    target: Target<'_>,
    pacing: Pacing<'_, S>,
    method: Method,
    body: Option<&Value>,
) -> Result<Response>
where
    T: Transport,
    A: TokenSource,
    S: Sleeper,
{
    let Pacing {
        timeout,
        retry,
        sleeper,
    } = pacing;
    let deadline = exchange_deadline(timeout, Instant::now());
    let url = request_url(target.base_url, target.allow_http_base_url, target.path)?;

    let token = auth.access_token(false).await?;
    let response = send_once(
        transport,
        &url,
        remaining_budget(deadline, Instant::now()),
        method,
        body,
        token.security(),
    )
    .await?;
    if response.status() != 401 {
        return Ok(response);
    }

    let retry_after = retry_after_from(|name| response.header(name));
    if let Some(delay) = retry_pause(retry, retry_after, deadline, Instant::now()) {
        sleeper.sleep(delay).await;
    }

    let token = auth.refresh_after(&token).await?;
    let response = send_once(
        transport,
        &url,
        remaining_budget(deadline, Instant::now()),
        method,
        body,
        token.security(),
    )
    .await?;
    if response.status() == 401 {
        return Err(Error::Unauthorized);
    }
    Ok(response)
}

/// The single deadline for an exchange, or `None` when the caller set no
/// per-request timeout and the transport default applies.
fn exchange_deadline(timeout: Option<Duration>, now: Instant) -> Option<Instant> {
    timeout.and_then(|timeout| now.checked_add(timeout))
}

/// What is left of the deadline, or `None` when there is no budget.
///
/// A spent budget yields `Duration::ZERO` rather than a negative duration, so
/// the next attempt is told to expire immediately instead of being handed a
/// value the transport cannot represent.
fn remaining_budget(deadline: Option<Instant>, now: Instant) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(now))
}

/// The wait before the single 401 resend: the policy's own arithmetic, clamped
/// so it can never sleep past the deadline.
///
/// `None` means the policy vetoes the retry (`RetryPolicy::none`), which leaves
/// the resend immediate — the historic behaviour for callers without a policy.
fn retry_pause(
    retry: &RetryPolicy,
    retry_after: Option<Duration>,
    deadline: Option<Instant>,
    now: Instant,
) -> Option<Duration> {
    let delay = retry.delay(1, retry_after)?;
    Some(match deadline {
        Some(deadline) => delay.min(deadline.saturating_duration_since(now)),
        None => delay,
    })
}

async fn send_once<T: Transport>(
    transport: &T,
    url: &str,
    timeout: Option<Duration>,
    method: Method,
    body: Option<&Value>,
    security: Security<'_>,
) -> Result<Response> {
    let request = match body {
        Some(body) => Request::json(method, url, security, body),
        None => Request::empty(method, url, security),
    }
    .with_timeout(timeout);
    transport.execute(request).await
}

/// Builds the final URL after checking both halves before a credential exists.
fn request_url(base_url: &str, allow_http_base_url: bool, path: &str) -> Result<String> {
    let base = Url::parse(base_url)
        .map_err(|error| Error::invalid_request("base_url", format!("must be a URL: {error}")))?;
    if !(base.scheme() == "https" || (allow_http_base_url && base.scheme() == "http")) {
        return Err(Error::invalid_request("base_url", "must use https://"));
    }
    if base.host_str().is_none() {
        return Err(Error::invalid_request("base_url", "must include a host"));
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err(Error::invalid_request(
            "base_url",
            "must not include credentials",
        ));
    }
    validate_path(path)?;

    let base = base.as_str().trim_end_matches('/');
    let url = format!("{base}{path}");
    let parsed = Url::parse(&url).map_err(|error| {
        Error::invalid_request("path", format!("must build an absolute URL: {error}"))
    })?;
    if !(parsed.scheme() == "https" || (allow_http_base_url && parsed.scheme() == "http"))
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::invalid_request(
            "path",
            "must not retarget the base URL",
        ));
    }
    Ok(url)
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(Error::invalid_request("path", "must start with /"));
    }
    if path.starts_with("//") {
        return Err(Error::invalid_request("path", "must not start with //"));
    }
    if path.contains('\r') || path.contains('\n') {
        return Err(Error::invalid_request("path", "must not contain CR or LF"));
    }
    let (path_only, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    if path_only.starts_with("//") {
        return Err(Error::invalid_request("path", "must not start with //"));
    }
    if query.is_some_and(|query| {
        query.contains('?') || query.contains('@') || query.contains('\r') || query.contains('\n')
    }) {
        return Err(Error::invalid_request(
            "path",
            "query must not contain ? or @",
        ));
    }
    let segments = path_only[1..].split('/').collect::<Vec<_>>();
    let last = segments.len().saturating_sub(1);
    for (index, segment) in segments.into_iter().enumerate() {
        if segment.is_empty() && index < last {
            return Err(Error::invalid_request(
                "path",
                "must not contain empty path segments",
            ));
        }
        if segment == ".." {
            return Err(Error::invalid_request(
                "path",
                "must not contain .. path segments",
            ));
        }
        if segment.starts_with('@') {
            return Err(Error::invalid_request(
                "path",
                "must not contain @ path segments",
            ));
        }
        if segment.contains('@') {
            return Err(Error::invalid_request(
                "path",
                "must not contain @ after the first segment",
            ));
        }
        if segment.contains(':') && index > 0 {
            return Err(Error::invalid_request(
                "path",
                "must not contain a scheme-like path segment",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        authorized, exchange_deadline, remaining_budget, request_url, retry_pause, Pacing, Target,
    };
    use crate::auth::{Token, TokenSource};
    use crate::error::Error;
    use crate::retry::RetryPolicy;
    use crate::transport::{Method, Request, Response, Transport};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct CountingAuth {
        calls: AtomicUsize,
    }

    impl TokenSource for CountingAuth {
        fn access_token(
            &self,
            _force_refresh: bool,
        ) -> impl std::future::Future<Output = crate::Result<Token>> + Send {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Token::from_json(&serde_json::json!({"access_token": "t"})))
        }

        fn invalidate(&self) {}
    }

    struct NeverTransport;

    impl Transport for NeverTransport {
        fn execute(
            &self,
            _: Request<'_>,
        ) -> impl std::future::Future<Output = crate::Result<Response>> {
            std::future::ready(Err(Error::transport_terminal(
                "transport must not be reached",
            )))
        }
    }

    #[test]
    fn request_urls_reject_paths_that_do_not_start_with_slash() {
        let error = request_url("https://api.sipgate.com", false, "v2/users")
            .expect_err("relative paths must not swallow the host");
        assert!(matches!(error, Error::InvalidRequest { field: "path", .. }));
        assert!(!error.is_retryable());
    }

    #[test]
    fn request_urls_reject_retargeting_paths() {
        for path in [
            "@evil.example/x",
            "/@evil.example/x",
            "//evil.example/x",
            "/v2/../users",
            "/v2/users?x=1?y=2",
            "/v2/users?@evil.example/x",
        ] {
            let error = request_url("https://api.sipgate.com", false, path).expect_err(path);
            assert!(
                matches!(error, Error::InvalidRequest { field: "path", .. }),
                "{path:?} produced {error:?}"
            );
            assert!(!error.is_retryable());
        }
    }

    #[test]
    fn request_urls_require_an_absolute_https_base() {
        for base_url in [
            "",
            "api.sipgate.com",
            "http://api.sipgate.com",
            "file:///tmp/x",
        ] {
            let error = request_url(base_url, false, "/v2/users").expect_err(base_url);
            assert!(
                matches!(
                    error,
                    Error::InvalidRequest {
                        field: "base_url",
                        ..
                    }
                ),
                "{base_url:?} produced {error:?}"
            );
            assert!(!error.is_retryable());
        }
    }

    #[test]
    fn request_urls_keep_the_same_shape_for_legitimate_paths_and_queries() {
        assert_eq!(
            request_url("https://api.sipgate.com/", false, "/v2/users").expect("valid"),
            "https://api.sipgate.com/v2/users"
        );
        assert_eq!(
            request_url("https://api.sipgate.com", false, "/v2/users?limit=10").expect("valid"),
            "https://api.sipgate.com/v2/users?limit=10"
        );
        assert_eq!(
            request_url("http://localhost:8080/", true, "/v2/users").expect("local testing"),
            "http://localhost:8080/v2/users"
        );
    }

    #[tokio::test]
    async fn invalid_request_urls_are_rejected_before_the_credential_is_fetched() {
        let auth = CountingAuth::default();
        let error = authorized(
            &NeverTransport,
            &auth,
            Target {
                base_url: "https://api.sipgate.com",
                allow_http_base_url: false,
                path: "@evil.example/x",
            },
            Pacing {
                timeout: None,
                retry: &RetryPolicy::none(),
                sleeper: &crate::retry::NoSleep,
            },
            Method::Get,
            None,
        )
        .await
        .expect_err("invalid request URL");

        assert!(matches!(error, Error::InvalidRequest { field: "path", .. }));
        assert!(!error.is_retryable());
        assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_missing_timeout_leaves_the_transport_default_in_place() {
        let now = Instant::now();
        assert_eq!(exchange_deadline(None, now), None);
        assert_eq!(remaining_budget(None, now), None);
        // No deadline to clamp against, so the policy's own delay stands.
        assert_eq!(
            retry_pause(
                &RetryPolicy::default(),
                Some(Duration::from_secs(1)),
                None,
                now
            ),
            Some(Duration::from_secs(1))
        );
        // Without a `Retry-After` hint the default policy jitters its backoff.
        let delay = retry_pause(&RetryPolicy::default(), None, None, now).expect("first retry");
        assert!(delay >= Duration::from_millis(125));
        assert!(delay <= Duration::from_millis(250));
    }

    #[test]
    fn the_deadline_is_taken_once_from_the_caller_timeout() {
        let now = Instant::now();
        let budget = Duration::from_secs(10);
        assert_eq!(exchange_deadline(Some(budget), now), Some(now + budget));
    }

    #[test]
    fn each_attempt_sees_only_what_is_left_of_the_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        // Nothing consumed yet: the first attempt gets the whole budget.
        assert_eq!(
            remaining_budget(Some(deadline), now),
            Some(Duration::from_secs(5))
        );
        // After 3 s the second attempt gets the 2 s that remain.
        assert_eq!(
            remaining_budget(Some(deadline), now + Duration::from_secs(3)),
            Some(Duration::from_secs(2))
        );
        // A spent budget is zero, never a negative duration.
        assert_eq!(
            remaining_budget(Some(deadline), now + Duration::from_secs(9)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn the_resend_delay_obeys_the_policy_ceiling() {
        let now = Instant::now();
        let retry = RetryPolicy::default();
        // A huge `Retry-After` is clamped to the policy's own ceiling; nothing
        // about the 401 path bypasses that arithmetic.
        assert_eq!(
            retry_pause(&retry, Some(Duration::from_secs(600)), None, now),
            Some(retry.max_delay)
        );
        let fast = RetryPolicy::default().with_max_delay(Duration::from_millis(100));
        assert_eq!(
            retry_pause(&fast, Some(Duration::from_secs(600)), None, now),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn the_resend_delay_is_clamped_to_the_remaining_budget() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(300);
        let retry = RetryPolicy::default();
        assert_eq!(
            retry_pause(&retry, Some(Duration::from_secs(600)), Some(deadline), now),
            Some(Duration::from_millis(300)),
            "a pause can never sleep past the caller's deadline"
        );
    }

    #[test]
    fn a_no_retry_policy_leaves_the_resend_immediate() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        assert_eq!(
            retry_pause(&RetryPolicy::none(), None, Some(deadline), now),
            None,
            "`RetryPolicy::none` vetoes the resend, so there is no pause"
        );
    }
}
