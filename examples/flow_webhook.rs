//! Answers a sipgate flow webhook without a socket: verify, parse, respond.
//!
//! Run it with `cargo run --example flow_webhook`. Nothing here touches the
//! network — a webhook handler is a pure function from (secret, content type,
//! body) to (status, JSON), which is exactly why it can be exercised like this.

use sipgate_flow::{Action, Error, EventPayload, FlowResponse, WebhookVerifier};

/// The secret the realm shows under "AI Flow" -> "Webhook"; sipgate sends it
/// back in `X-API-TOKEN` and the verifier compares it in constant time.
const SHARED_SECRET: &str = "shared-secret-from-your-realm";

fn main() -> Result<(), Error> {
    let verifier = WebhookVerifier::new(SHARED_SECRET)?;

    // A caller asks for an appointment; the handler answers with an action,
    // not with a separate request.
    let spoken = br#"{
        "type": "user_speak",
        "text": "Ich brauche einen Termin",
        "barged_in": false,
        "session": {"id": "s-42", "direction": "inbound"}
    }"#;
    let event = verifier.verify_and_parse(Some(SHARED_SECRET), Some("application/json"), spoken)?;

    let response = match event.payload() {
        EventPayload::UserSpeak { text, .. } if text.contains("Termin") => {
            let session = event.session_id().unwrap_or_default();
            FlowResponse::many([
                Action::speak(session, "Einen Moment, ich schaue nach.")?,
                Action::hangup(session)?,
            ])
        }
        _ => FlowResponse::none(),
    };
    // 200 with a body means "run these actions"; 204 means "say nothing".
    assert_eq!(response.status(), 200);
    assert_eq!(response.len(), 2);
    println!("200 {}", response.body().unwrap_or_default());

    // `session_end` must not be answered with an action, so this yields 204.
    let ended = br#"{"type":"session_end","session":{"id":"s-42"}}"#;
    let event = verifier.verify_and_parse(Some(SHARED_SECRET), Some("application/json"), ended)?;
    let silence = FlowResponse::none();
    assert_eq!(silence.status(), 204);
    println!("{} for {:?}", silence.status(), event.payload());

    // A wrong secret is refused before the body is parsed at all.
    let refused = verifier.verify_and_parse(Some("wrong"), Some("application/json"), spoken);
    match refused {
        Err(Error::SecretMismatch) => println!("rejected a wrong X-API-TOKEN"),
        Err(other) => panic!("expected a mismatch, got {other:?}"),
        Ok(_) => panic!("a wrong secret was accepted"),
    }
    Ok(())
}
