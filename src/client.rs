//! HTTP client for flow actions.

use crate::action::Action;
use crate::error::Result;

/// Sends actions to the sipgate flow endpoint.
#[derive(Debug, Clone)]
pub struct SipgateFlowClient {
    base_url: String,
    token: String,
    #[cfg(feature = "http")]
    http: reqwest::Client,
}

impl SipgateFlowClient {
    /// Creates a client. `base_url` is explicit because the path is not
    /// byte-documented and differs per deployment.
    #[must_use]
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token: token.into(),
            #[cfg(feature = "http")]
            http: reqwest::Client::new(),
        }
    }

    /// URL an action for `call_id` is posted to.
    #[must_use]
    pub fn action_url(&self, call_id: &str) -> String {
        format!(
            "{}/calls/{}/actions",
            self.base_url.trim_end_matches('/'),
            call_id
        )
    }

    /// Posts `action` for `call_id`.
    ///
    /// # Errors
    ///
    /// Propagates transport and API errors.
    #[cfg(feature = "http")]
    pub async fn execute(&self, call_id: &str, action: &Action) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(self.action_url(call_id))
            .bearer_auth(&self.token)
            .json(&action.to_json())
            .send()
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| crate::Error::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(crate::Error::Api {
                status: status.as_u16(),
                body,
            });
        }
        if body.trim().is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_str(&body).map_err(|e| crate::Error::Payload(e.to_string()))
    }
}
