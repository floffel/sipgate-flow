//! The authenticated request exchange shared by both clients.
//!
//! One rule lives here and only here: a 401 means the cached bearer is stale,
//! so the token is invalidated, fetched once with `force_refresh`, and the
//! request is retried exactly once. A second 401 is terminal — retrying it
//! would burn rate limit for nothing.

use serde_json::Value;
use std::time::Duration;

use crate::auth::TokenSource;
use crate::error::{Error, Result};
use crate::transport::{Method, Request, Response, Security, Transport};

/// Sends `method path` with a bearer token, refreshing once on 401.
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
        token.access_token(),
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
        token.access_token(),
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
    token: &str,
) -> Result<Response> {
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let request = match body {
        Some(body) => Request::json(method, &url, Security::Bearer(token), body),
        None => Request::empty(method, &url, Security::Bearer(token)),
    }
    .with_timeout(timeout);
    transport.execute(request).await
}
