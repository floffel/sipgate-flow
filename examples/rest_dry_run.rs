//! Drives the REST client against a recording transport instead of the network.
//!
//! Run it with `cargo run --example rest_dry_run`. It prints the request the
//! crate would send and the decoded receipt, so a real call is one
//! `ReqwestTransport::new()` away — and the example doubles as the recipe for
//! testing your own handlers without a sipgate account.

use std::future::Future;

use sipgate_flow::rest::Sms;
use sipgate_flow::transport::{Request, RequestBody, Response};
use sipgate_flow::{RestClient, Result, StaticToken, Transport};

/// Prints every request and answers with a canned body. A real transport lives
/// behind the `http` feature; this one keeps the example offline.
struct Recording;

impl Transport for Recording {
    fn execute(&self, request: Request<'_>) -> impl Future<Output = Result<Response>> + Send {
        let body = match &request.body {
            RequestBody::Empty => " (no body)".to_string(),
            RequestBody::Json(json) => format!(" {json}"),
            RequestBody::Form(fields) => format!(" {} form fields", fields.len()),
            // `RequestBody` is `#[non_exhaustive]`: a body kind added later is
            // printed without its payload instead of breaking this example.
            other => format!(" {other:?}"),
        };
        println!("-> {} {}{body}", request.method.as_str(), request.url);
        std::future::ready(Ok(Response::new(
            200,
            std::iter::empty(),
            br#"{"id":"sms-7"}"#.to_vec(),
        )))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // A Personal Access Token goes out as `Basic base64(<token id>:<token>)`,
    // which `StaticToken` applies; an `OAuth2Client` produces a bearer token.
    let client = RestClient::new(Recording, StaticToken::new("personal-access-token")?);
    let receipt = client
        .send_sms(&Sms::new("s0", "4915112345678", "Ihr Termin: Di 14:30")?)
        .await?;
    println!("<- {receipt}");
    Ok(())
}
