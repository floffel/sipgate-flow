//! Answers a classic Push API request without a socket: decode, render, reply.
//!
//! Run it with `cargo run --example push_webhook`. Nothing here touches the
//! network — a Push API handler is a pure function from (content type, body) to
//! (status, XML), which is exactly why it can be exercised like this.

use sipgate_flow::push::{
    Dial, Gather, Play, PushAction, PushEventKind, PushResponse, PushVerifier,
};
use sipgate_flow::Error;

fn main() -> Result<(), Error> {
    let verifier = PushVerifier::new();

    // A call arrives. The reference documents the body as
    // `application/x-www-form-urlencoded`; the handler answers with XML.
    let new_call = b"event=newCall&from=492111234567&to=4915791234567&direction=in\
                     &callId=123456&user[]=Alice&userId[]=w0&fullUserId[]=1234567w0";
    let event = verifier.verify_and_parse(Some("application/x-www-form-urlencoded"), new_call)?;
    println!(
        "newCall {} from {:?} to {:?}",
        event.call_id().unwrap_or_default(),
        event.from(),
        event.to()
    );

    // Ask for one digit and play a prompt while collecting it.
    let menu = PushResponse::new()
        .with_on_hangup("https://example.com/hangup")?
        .with_verb(PushAction::gather(
            Gather::new("https://example.com/dtmf")?
                .with_max_digits(1)?
                .with_play(Play::new("https://example.com/menu.wav")?),
        ));
    assert_eq!(menu.status(), 200);
    assert_eq!(menu.content_type(), "application/xml");
    println!("{}", menu.to_xml());

    // The gather callback always fires; an empty `dtmf` means no digit.
    let callback = b"event=dtmf&dtmf=1&callId=123456";
    let digits = verifier.verify_and_parse(Some("application/x-www-form-urlencoded"), callback)?;
    assert_eq!(digits.kind(), &PushEventKind::Dtmf);

    let forward =
        PushResponse::new().with_verb(PushAction::dial(Dial::to_number("4915799912345")?));
    println!("{}", forward.to_xml());

    // JSON is Flow, not the Push API, and is refused before it is parsed.
    match verifier.verify_and_parse(Some("application/json"), br#"{"type":"newCall"}"#) {
        Err(Error::UnsupportedContentType { .. }) => println!("rejected a JSON body"),
        Err(other) => panic!("expected a content-type rejection, got {other:?}"),
        Ok(_) => panic!("a JSON body was accepted by the Push verifier"),
    }

    Ok(())
}
