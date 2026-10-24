//! The authenticated request exchange shared by both clients.
//!
//! One rule lives here and only here: a 401 means the cached credential is
//! stale, so it is invalidated, fetched once with `force_refresh`, and the
//! request is retried exactly once. A second 401 is terminal — retrying it
//! would burn rate limit for nothing.
//!
//! The header the credential goes out with comes from
//! [`Token::security`](crate::auth::Token::security), not from this module: a
//! PAT is `Basic id:token`, an access token is `Bearer`, and neither should be
//! spelled out twice.

use serde_json::Value;
use std::time::Duration;

use crate::auth::TokenSource;
use crate::error::{Error, Result};
use crate::transport::{Method, Request, Response, Security, Transport};

/// Sends `method path` with the credential's scheme, refreshing once on 401.
///
/// `base_url` is joined without a trailing slash; `path` must start with `/`.
pub(crate) async fn authorized<T: Transport, A: TokenSource>(
    transport: &T,
    auth: &A,
    base_url: &str,
    timeout: Option<Duration>,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Response> {
    let token = auth.access_token(false).await?;
    let response = send_once(
        transport,
        base_url,
        timeout,
        method,
        path,
        body,
        token.security(),
    )
    .await?;
    if response.status() != 401 {
        return Ok(response);
    }

    auth.invalidate();
    let token = auth.access_token(true).await?;
    let response = send_once(
        transport,
        base_url,
        timeout,
        method,
        path,
        body,
        token.security(),
    )
    .await?;
    if response.status() == 401 {
        return Err(Error::Unauthorized);
    }
    Ok(response)
}

async fn send_once<T: Transport>(
    transport: &T,
    base_url: &str,
    timeout: Option<Duration>,
    method: Method,
    path: &str,
    body: Option<&Value>,
    security: Security<'_>,
) -> Result<Response> {
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let request = match body {
        Some(body) => Request::json(method, &url, security, body),
        None => Request::empty(method, &url, security),
    }
    .with_timeout(timeout);
    transport.execute(request).await
}
