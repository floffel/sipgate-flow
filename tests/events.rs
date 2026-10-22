//! Parsing of flow events, including tolerance for the undocumented parts.

use sipgate_flow::Event;

#[test]
fn parses_answered_with_camel_case_call_id() {
    let event = Event::parse(br#"{"event":"answered","callId":"abc-1"}"#).unwrap();
    assert_eq!(
        event,
        Event::Answered {
            call_id: "abc-1".into()
        }
    );
}

#[test]
fn parses_dtmf_and_speech() {
    let dtmf = Event::parse(br#"{"event":"dtmf","callId":"c","digits":"2"}"#).unwrap();
    assert_eq!(
        dtmf,
        Event::Dtmf {
            call_id: "c".into(),
            digits: "2".into()
        }
    );

    let speech = Event::parse(br#"{"type":"speech","call_id":"c","transcript":"Hallo"}"#).unwrap();
    assert_eq!(
        speech,
        Event::Speech {
            call_id: "c".into(),
            text: "Hallo".into()
        }
    );
}

#[test]
fn parses_hangup_with_and_without_cause() {
    let with = Event::parse(br#"{"event":"hangup","callId":"c","cause":"normal"}"#).unwrap();
    assert_eq!(
        with,
        Event::Hangup {
            call_id: "c".into(),
            cause: Some("normal".into())
        }
    );

    let without = Event::parse(br#"{"event":"ended","callId":"c"}"#).unwrap();
    assert_eq!(
        without,
        Event::Hangup {
            call_id: "c".into(),
            cause: None
        }
    );
}

#[test]
fn unknown_events_do_not_fail() {
    let event = Event::parse(br#"{"event":"recording_ready","callId":"c"}"#).unwrap();
    assert_eq!(
        event,
        Event::Unknown {
            kind: "recording_ready".into()
        }
    );
    assert_eq!(event.call_id(), None);

    let missing = Event::parse(br#"{"callId":"c"}"#).unwrap();
    assert_eq!(
        missing,
        Event::Unknown {
            kind: String::new()
        }
    );
}

#[test]
fn extra_fields_are_ignored() {
    let event = Event::parse(br#"{"event":"answered","callId":"c","foo":{"bar":1}}"#).unwrap();
    assert!(matches!(event, Event::Answered { .. }));
}

#[test]
fn invalid_json_is_an_error() {
    assert!(Event::parse(b"not json").is_err());
}
