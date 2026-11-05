//! REST v2: documented method/path/body per endpoint, the retry budget, the
//! 401 refresh, and concurrency.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    json_response, no_content, response, static_auth, Body, MockTransport, RecordingSleeper,
};
use sipgate_flow::rest::{
    Announcement, BlockAnonymousTarget, Call, ChannelCall, DeleteHistoryEntriesRequest, DeviceKind,
    Dtmf, Fax, HistoryDirection, HistoryEntryKind, HistoryEntryUpdate, HistoryExportRequest,
    HistoryQuery, HistoryStarred, ParallelForwardingRequest, PhonelineAlias,
    PhonelineBlockAnonymousSetting, PhonelineForwardingRule, PhonelineForwardings,
    PhonelineNumberKind, PhonelineSipgateIo, PlayVoicemail, Recording, RecordingSession, ResendFax,
    RouteDeviceRequest, SetHistoryEntryArchiveRequest, SetHistoryEntryNoteRequest,
    SetHistoryEntryReadRequest, Sms, TransferRequest, UpdateHistoryEntriesRequest,
    UpdateHistoryEntryRequest, VoicemailGreetingRequest, VoicemailGreetingUpdate,
    VoicemailSettingsUpdate, VoicemailTranscriptionUpdate, MAX_HISTORY_LIMIT, MAX_HISTORY_OFFSET,
    MAX_HISTORY_UPDATE_ENTRIES,
};
use sipgate_flow::{
    ClientCredentials, Error, OAuth2Client, RestClient, Result, RetryPolicy, RetryPolicy as Policy,
    StaticToken, Token, TokenSource,
};

type TestClient = RestClient<MockTransport, StaticToken, RecordingSleeper>;

fn harness() -> (MockTransport, RecordingSleeper, TestClient) {
    let transport = MockTransport::new();
    let sleeper = RecordingSleeper::new();
    let client = RestClient::new(transport.clone(), static_auth()).with_sleeper(sleeper.clone());
    (transport, sleeper, client)
}

fn json_body(body: &Body) -> serde_json::Value {
    match body {
        Body::Json(value) => value.clone(),
        other => panic!("expected a JSON body, got {other:?}"),
    }
}

#[tokio::test]
async fn send_sms_posts_the_documented_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    let sms = Sms::new("s0", "4915112345678", "Ihr Code: 4242").expect("valid");
    client.send_sms(&sms).await.expect("sent");

    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "POST");
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/sms");
    assert_eq!(call.auth.bearer(), Some("access-token"));
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!("fixtures/rest/sms_request.json"))
            .expect("fixture")
    );
}

#[tokio::test]
async fn send_fax_posts_content_and_returns_the_session_id() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(
        &serde_json::from_str(include_str!("fixtures/rest/fax_response.json")).expect("fixture"),
    ));
    let fax = Fax::new("f0", "4921112345678", "fax.pdf", "JVBERi0xLjQK").expect("valid");
    let value = client.send_fax(&fax).await.expect("sent");
    assert_eq!(value["sessionId"], "f-session-1");

    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/fax");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!("fixtures/rest/fax_request.json"))
            .expect("fixture")
    );
}

#[tokio::test]
async fn a_fax_larger_than_the_documented_ceiling_is_refused_before_sending() {
    let content = "A".repeat(sipgate_flow::rest::MAX_FAX_BASE64_LEN + 4);
    let error = Fax::new("f0", "4915112345678", "big.pdf", content).expect_err("too large");
    assert!(matches!(
        error,
        Error::Validation {
            field: "base64Content",
            ..
        }
    ));
}

#[tokio::test]
async fn resend_fax_uses_its_own_path() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "s"})));
    client
        .resend_fax(&ResendFax::new("100018428").with_faxline_id("f0"))
        .await
        .expect("resent");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/fax/resend");
    assert_eq!(json_body(&call.body)["faxId"], "100018428");
}

#[tokio::test]
async fn new_call_posts_caller_and_callee() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "c-1"})));
    let call = Call::new("e0", "4915112345678").expect("valid");
    client.new_call(&call).await.expect("called");

    let recorded = transport.only_call();
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/sessions/calls");
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/new_call_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn channel_call_posts_the_neo_pbx_shape() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"callSid": "x"})));
    client
        .channel_call(&ChannelCall::new("e0", "4915790123456"))
        .await
        .expect("called");
    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/calls");
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/create_call_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn recording_sessions_route_to_their_own_paths() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "r1"})));
    transport.push_response(json_response(&serde_json::json!({"sessionId": "r2"})));
    let request = RecordingSession::new()
        .with_device_id("e0")
        .with_target_id("v0");
    client.record_ivr(&request).await.expect("ivr");
    client.record_voicemail(&request).await.expect("voicemail");

    let calls = transport.calls();
    assert_eq!(
        calls[0].url,
        "https://api.sipgate.com/v2/sessions/ivr/recording"
    );
    assert_eq!(
        calls[1].url,
        "https://api.sipgate.com/v2/sessions/voicemail/recording"
    );
    assert_eq!(json_body(&calls[0].body)["targetId"], "v0");
}

#[tokio::test]
async fn voicemail_playback_keeps_the_documents_datad_id_key() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "p1"})));
    client
        .play_voicemail(&PlayVoicemail::new("1000171", "e0"))
        .await
        .expect("played");

    let recorded = transport.only_call();
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v2/sessions/voicemail/play"
    );
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/play_voicemail_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn hangup_is_a_delete_without_a_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client.hangup("ABCDEF0123456789").await.expect("hung up");
    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "DELETE");
    assert_eq!(
        call.url,
        "https://api.sipgate.com/v2/calls/ABCDEF0123456789"
    );
    assert_eq!(call.body, Body::Empty);
}

#[tokio::test]
async fn dtmf_posts_the_sequence() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .send_dtmf("c1", &Dtmf::new("123456").expect("valid"))
        .await
        .expect("sent");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/dtmf");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!("fixtures/rest/dtmf_request.json"))
            .expect("fixture")
    );
}

#[tokio::test]
async fn announcements_post_the_url() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    let announcement =
        Announcement::new("https://static.sipgate.com/examples/wav/example.wav").expect("valid");
    client.announce("c1", &announcement).await.expect("played");
    let call = transport.only_call();
    assert_eq!(
        call.url,
        "https://api.sipgate.com/v2/calls/c1/announcements"
    );
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/announcement_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn recording_uses_put_and_the_documented_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .set_recording("c1", &Recording::start())
        .await
        .expect("recording");
    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "PUT");
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/recording");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/recording_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn hold_and_mute_put_a_boolean_value() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    transport.push_response(no_content());
    client.set_hold("c1", true).await.expect("hold");
    client.set_muted("c1", false).await.expect("mute");

    let calls = transport.calls();
    assert_eq!(calls[0].method.as_str(), "PUT");
    assert_eq!(calls[0].url, "https://api.sipgate.com/v2/calls/c1/hold");
    assert_eq!(
        json_body(&calls[0].body),
        serde_json::json!({"value": true})
    );
    assert_eq!(calls[1].url, "https://api.sipgate.com/v2/calls/c1/muted");
    assert_eq!(
        json_body(&calls[1].body),
        serde_json::json!({"value": false})
    );
}

#[tokio::test]
async fn transfer_posts_attend_and_number() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .transfer(
            "c1",
            &TransferRequest::blind("4915112345678").expect("valid"),
        )
        .await
        .expect("transferred");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/transfer");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/transfer_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn the_call_list_is_parsed_into_types() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(
        &serde_json::from_str(include_str!("fixtures/rest/calls_response.json")).expect("fixture"),
    ));
    let calls = client.calls().await.expect("listed");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].call_id, "ABCDEF0123456789");
    assert!(calls[0].recording);
    assert!(calls[0].participants[0].owner);

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/calls");
}

#[tokio::test]
async fn devices_contacts_history_and_phonelines_are_typed_get_reads() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "id": "e0",
        "alias": "Desk phone",
        "type": "REGISTER",
        "dnd": false,
        "online": true,
        "activeGroups": [{"id": "g0", "alias": "Sales"}],
        "activePhonelines": [{"id": "p0", "alias": "Front desk"}],
        "futureField": 1
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "contact-1",
            "name": "Ada Lovelace",
            "givenname": "Ada",
            "familyname": "Lovelace",
            "scope": "PRIVATE",
            "numbers": [{"id": "n1", "number": "+4915112345678", "localized": "01579-9912345", "type": "MOBILE"}],
            "futureField": true
        }]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "id": "contact-1",
        "name": "Ada Lovelace",
        "givenname": "Ada",
        "familyname": "Lovelace",
        "scope": "PRIVATE",
        "numbers": [],
        "futureField": true
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "100001234",
            "type": "CALL",
            "direction": "INCOMING",
            "status": "PICKUP",
            "created": "2016-02-10T14:19:39Z",
            "endpoints": [{"type": "ROUTED", "endpoint": {"extension": "e0", "type": "REGISTER"}}],
            "futureField": 1
        }],
        "totalCount": 1
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "p0",
            "alias": "Front desk",
            "userId": "w0",
            "voicemails": [{"id": "v0", "active": true, "timeout": 20}],
            "futureField": true
        }]
    })));

    let device = client.device("e0").await.expect("device");
    assert_eq!(device.id, "e0");
    assert_eq!(device.kind, Some(DeviceKind::Register));
    assert!(device.online);
    assert_eq!(device.active_groups[0].alias, "Sales");

    let contacts = client.contacts().await.expect("contacts");
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "Ada Lovelace");
    assert_eq!(contacts[0].numbers[0].number, "+4915112345678");

    let contact = client.contact("contact-1").await.expect("contact");
    assert_eq!(contact.familyname, "Lovelace");
    assert_eq!(
        contact
            .scope
            .as_ref()
            .map(sipgate_flow::rest::ContactScope::as_str),
        Some("private")
    );

    let history = client.history().await.expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, "100001234");
    assert_eq!(history[0].kind, Some(HistoryEntryKind::Call));
    assert_eq!(
        history[0].endpoints[0].endpoint.as_ref().unwrap().extension,
        "e0"
    );

    let phonelines = client.phonelines().await.expect("phonelines");
    assert_eq!(phonelines.len(), 1);
    assert_eq!(phonelines[0].user_id, "w0");
    assert!(phonelines[0].voicemails[0].active);

    let calls = transport.calls();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[0].method.as_str(), "GET");
    assert_eq!(calls[0].url, "https://api.sipgate.com/v2/devices/e0");
    assert_eq!(calls[1].url, "https://api.sipgate.com/v2/contacts");
    assert_eq!(
        calls[2].url,
        "https://api.sipgate.com/v2/contacts/contact-1"
    );
    assert_eq!(calls[3].url, "https://api.sipgate.com/v2/history");
    assert_eq!(calls[4].url, "https://api.sipgate.com/v2/phonelines");
    for call in calls {
        assert_eq!(call.body, Body::Empty);
        assert_eq!(call.auth.bearer(), Some("access-token"));
    }
}

#[tokio::test]
async fn empty_rest_lists_and_empty_objects_still_decode_permissively() {
    let (transport, _, client) = harness();
    let empty_list = serde_json::json!({"items": null, "totalCount": 0});
    for _ in 0..3 {
        transport.push_response(json_response(&empty_list));
    }
    transport.push_response(json_response(&serde_json::json!({})));

    assert_eq!(client.contacts().await.expect("contacts"), []);
    assert_eq!(client.history().await.expect("history"), []);
    assert_eq!(client.phonelines().await.expect("phonelines"), []);
    let device = client.device("e0").await.expect("empty device defaults");
    assert_eq!(device, sipgate_flow::rest::Device::default());
}

#[tokio::test]
async fn the_account_admin_id_parameters_are_validated_before_the_wire() {
    let (transport, _, client) = harness();
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "../devices",
        "a?b",
        "a b",
        "a#b",
        "a\tb",
    ] {
        let device_error = client.device(bad).await.expect_err(bad);
        let contact_error = client.contact(bad).await.expect_err(bad);
        assert!(
            matches!(
                device_error,
                Error::Validation {
                    field: "device_id",
                    ..
                }
            ),
            "{bad:?} produced {device_error:?}"
        );
        assert!(
            matches!(
                contact_error,
                Error::Validation {
                    field: "contact_id",
                    ..
                }
            ),
            "{bad:?} produced {contact_error:?}"
        );
    }
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn rest_admin_list_envelopes_accept_just_inside_ids_and_just_outside_ids() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"items": []})));
    transport.push_response(json_response(&serde_json::json!({"items": []})));

    let just_inside = "a".repeat(200);
    let just_outside = "a".repeat(201);
    assert!(client.device(&just_inside).await.is_ok());
    assert!(matches!(
        client.device(&just_outside).await,
        Err(Error::Validation {
            field: "device_id",
            ..
        })
    ));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn device_and_contact_get_responses_reject_a_type_mismatch() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"id": 1})));
    transport.push_response(json_response(&serde_json::json!({"id": 1})));

    assert!(client.device("e0").await.is_err());
    assert!(client.contact("c1").await.is_err());
}

#[tokio::test]
async fn account_admin_models_decode_camel_case_and_snake_case_aliases() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "id": "e0",
        "alias": "Desk phone",
        "type": "appliance",
        "active_groups": [{"id": "g0", "alias": "Sales"}],
        "active_phonelines": []
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "100001234",
            "type": "page",
            "direction": "missed_incoming",
            "last_modified": "2016-02-10T14:19:39Z",
            "source_alias": "Dennis Ritchie",
            "target_alias": "Ken Thompson",
            "connection_ids": ["c1"],
            "endpoints": [{
                "type": "telepathy",
                "endpoint": {"extension": "e0", "type": "future"}
            }]
        }]
    })));

    let device = client.device("e0").await.expect("device");
    assert_eq!(device.kind, Some(DeviceKind::Other("appliance".into())));
    assert_eq!(device.active_groups[0].alias, "Sales");

    let history = client.history().await.expect("history");
    assert_eq!(history[0].last_modified, "2016-02-10T14:19:39Z");
    assert_eq!(history[0].source_alias, "Dennis Ritchie");
    assert_eq!(history[0].target_alias, "Ken Thompson");
    assert_eq!(history[0].connection_ids, ["c1"]);
    assert_eq!(
        history[0].endpoints[0].kind,
        Some(sipgate_flow::rest::RoutedEndpointKind::Other(
            "telepathy".into()
        ))
    );
}

#[tokio::test]
async fn a_call_id_that_would_escape_the_path_is_refused_before_sending() {
    let (transport, _, client) = harness();
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "../calls",
        "a?b",
        "a b",
        "a#b",
        "a\tb",
        "abc\u{202e}gnp.exe",
        "abc\u{200b}def",
    ] {
        let error = client.hangup(bad).await.expect_err(bad);
        assert!(
            matches!(
                error,
                Error::Validation {
                    field: "call_id",
                    ..
                }
            ),
            "{bad:?} produced {error:?}"
        );
    }
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn the_history_resource_hits_every_documented_endpoint() {
    let (transport, _, client) = harness();
    push_history_responses(&transport);
    exercise_history_reads(&client).await;
    exercise_history_writes(&client).await;
    assert_history_requests(&transport);
}

fn push_history_responses(transport: &MockTransport) {
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "100001234",
            "type": "CALL",
            "direction": "MISSED_INCOMING",
            "status": "NOPICKUP",
            "created": "2016-02-10T14:19:39Z",
            "lastModified": "2016-02-10T14:20:39Z",
            "source": "anonymous",
            "sourceAlias": "Dennis Ritchie",
            "target": "01579-9912345",
            "targetAlias": "Ken Thompson",
            "archived": false,
            "incoming": true,
            "starred": false,
            "read": true,
            "labels": ["support"],
            "connectionIds": ["c1"],
            "endpoints": [{
                "type": "ROUTED",
                "endpoint": {"extension": "e0", "type": "REGISTER"}
            }],
            "futureField": {"kept": true}
        }],
        "totalCount": 1,
        "futureEnvelopeField": "ignored"
    })));
    transport.push_response(json_response(&serde_json::json!({
        "id": "100001234",
        "type": "CALL",
        "direction": "INCOMING",
        "futureField": 1
    })));
    transport.push_response(response(
        200,
        &[("Content-Type", "application/octet-stream")],
        b"id,type\n100001234,CALL\n",
    ));
    for _ in 0..7 {
        transport.push_response(no_content());
    }
}

async fn exercise_history_reads(client: &TestClient) {
    let page = client
        .history_page(&full_history_query())
        .await
        .expect("history page");
    assert_eq!(page.total_count, Some(1));
    assert_eq!(page.items[0].id, "100001234");
    assert_eq!(page.items[0].kind, Some(HistoryEntryKind::Call));
    assert_eq!(
        page.items[0].direction,
        Some(HistoryDirection::MissedIncoming)
    );
    assert_eq!(
        page.items[0].endpoints[0]
            .endpoint
            .as_ref()
            .map(|e| e.extension.as_str()),
        Some("e0")
    );

    let entry = client.history_entry("100001234").await.expect("entry");
    assert_eq!(entry.id, "100001234");

    let mut export_query = HistoryQuery::new();
    export_query.limit = Some(5);
    let csv = client
        .history_export_csv(&HistoryExportRequest::new(export_query))
        .await
        .expect("csv");
    assert_eq!(csv, "id,type\n100001234,CALL\n");
}

async fn exercise_history_writes(client: &TestClient) {
    client
        .delete_history_entries(&delete_history_request())
        .await
        .expect("deleted many");
    client
        .delete_history_entry("100001236")
        .await
        .expect("deleted one");
    client
        .update_history_entries(&bulk_history_update())
        .await
        .expect("updated many");
    client
        .update_history_entry("100001234", &single_history_update())
        .await
        .expect("updated one");
    client
        .set_history_entry_archive("100001234", &SetHistoryEntryArchiveRequest::new(true))
        .await
        .expect("archived");
    client
        .set_history_entry_note(
            "100001234",
            &SetHistoryEntryNoteRequest::new("done").expect("note"),
        )
        .await
        .expect("noted");
    client
        .set_history_entry_read("100001234", &SetHistoryEntryReadRequest::new(false))
        .await
        .expect("read state");
}

fn full_history_query() -> HistoryQuery {
    let mut query = HistoryQuery::new();
    query.types = vec![HistoryEntryKind::Call, HistoryEntryKind::Sms];
    query.directions = vec![HistoryDirection::Incoming, HistoryDirection::MissedOutgoing];
    query.starred = vec![HistoryStarred::Starred, HistoryStarred::Unstarred];
    query.offset = Some(0);
    query.limit = Some(MAX_HISTORY_LIMIT);
    query.archived = Some(false);
    query.from = Some("2016-02-01T00:00:00Z".to_string());
    query.to = Some("2016-02-29T23:59:59Z".to_string());
    query.phone_number = Some("+4915112345678".to_string());
    query.include_all_users = Some(true);
    query.connection_ids = vec!["c1".to_string(), "c2".to_string()];
    query
}

fn delete_history_request() -> DeleteHistoryEntriesRequest {
    DeleteHistoryEntriesRequest::new(["100001234".to_string(), "100001235".to_string()])
        .expect("delete request")
}

fn bulk_history_update() -> UpdateHistoryEntriesRequest {
    let mut update = HistoryEntryUpdate::new("100001234").expect("update");
    update.archived = Some(false);
    update.read = Some(true);
    update.starred = Some(true);
    UpdateHistoryEntriesRequest::new([update]).expect("bulk update")
}

fn single_history_update() -> UpdateHistoryEntryRequest {
    let mut update = UpdateHistoryEntryRequest::new();
    update.archived = Some(false);
    update.read = Some(true);
    update.starred = Some(false);
    update.note = Some("called back".to_string());
    update
}

fn assert_history_requests(transport: &MockTransport) {
    let calls = transport.calls();
    assert_eq!(calls.len(), 10);
    let expected_methods = [
        "GET", "GET", "GET", "DELETE", "DELETE", "PUT", "PUT", "PUT", "PUT", "PUT",
    ];
    for (call, method) in calls.iter().zip(expected_methods) {
        assert_eq!(call.method.as_str(), method);
    }

    assert_eq!(
        calls[0].url,
        "https://api.sipgate.com/v2/history?types=CALL&types=SMS&directions=INCOMING&directions=MISSED_OUTGOING&offset=0&limit=1000&archived=false&starred=STARRED&starred=UNSTARRED&from=2016-02-01T00%3A00%3A00Z&to=2016-02-29T23%3A59%3A59Z&phonenumber=%2B4915112345678&includeAllUsers=true&connectionIds=c1&connectionIds=c2"
    );
    assert_eq!(calls[1].url, "https://api.sipgate.com/v2/history/100001234");
    assert_eq!(
        calls[2].url,
        "https://api.sipgate.com/v2/history/export?limit=5"
    );
    assert_eq!(
        calls[3].url,
        "https://api.sipgate.com/v2/history?id=100001234&id=100001235"
    );
    assert_eq!(calls[4].url, "https://api.sipgate.com/v2/history/100001236");
    assert_eq!(calls[5].url, "https://api.sipgate.com/v2/history");
    assert_eq!(calls[6].url, "https://api.sipgate.com/v2/history/100001234");
    assert_eq!(
        calls[7].url,
        "https://api.sipgate.com/v2/history/100001234/archive"
    );
    assert_eq!(
        calls[8].url,
        "https://api.sipgate.com/v2/history/100001234/note"
    );
    assert_eq!(
        calls[9].url,
        "https://api.sipgate.com/v2/history/100001234/read"
    );

    assert_eq!(
        json_body(&calls[5].body),
        serde_json::json!([{"id": "100001234", "archived": false, "read": true, "starred": true}])
    );
    assert_eq!(
        json_body(&calls[6].body),
        serde_json::json!({"archived": false, "read": true, "starred": false, "note": "called back"})
    );
    assert_eq!(
        json_body(&calls[7].body),
        serde_json::json!({"value": true})
    );
    assert_eq!(
        json_body(&calls[8].body),
        serde_json::json!({"note": "done"})
    );
    assert_eq!(
        json_body(&calls[9].body),
        serde_json::json!({"value": false})
    );
    for call in &calls[3..] {
        assert_eq!(call.auth.bearer(), Some("access-token"));
    }
}

#[test]
fn history_query_validation_has_just_inside_and_just_outside_bounds() {
    let mut query = HistoryQuery::new();
    query.offset = Some(MAX_HISTORY_OFFSET);
    query.limit = Some(MAX_HISTORY_LIMIT);
    assert!(query.to_query().is_ok());

    query.offset = Some(MAX_HISTORY_OFFSET + 1);
    assert!(matches!(
        query.to_query(),
        Err(Error::Validation {
            field: "offset",
            ..
        })
    ));

    query.offset = None;
    query.limit = Some(MAX_HISTORY_LIMIT + 1);
    assert!(matches!(
        query.to_query(),
        Err(Error::Validation { field: "limit", .. })
    ));

    query.limit = Some(0);
    assert_eq!(query.to_query().expect("zero is documented"), "limit=0");
}

#[test]
fn history_filter_writes_refuse_empty_or_escaping_values() {
    let mut query = HistoryQuery::new();
    query.connection_ids = vec!["a/b".to_string()];
    assert!(matches!(
        query.to_query(),
        Err(Error::Validation {
            field: "connectionIds",
            ..
        })
    ));

    let mut query = HistoryQuery::new();
    query.from = Some(String::new());
    assert!(matches!(
        query.to_query(),
        Err(Error::Validation { field: "from", .. })
    ));

    let mut query = HistoryQuery::new();
    query.phone_number = Some("+4915112345678".to_string());
    assert!(matches!(
        HistoryExportRequest::new(query).to_query(),
        Err(Error::Validation {
            field: "phonenumber",
            ..
        })
    ));
}

#[test]
fn history_update_requests_enforce_the_documented_bulk_limit_and_ids() {
    let just_inside = (0..MAX_HISTORY_UPDATE_ENTRIES)
        .map(|index| HistoryEntryUpdate::new(format!("entry-{index}")).expect("valid"))
        .collect::<Vec<_>>();
    assert!(UpdateHistoryEntriesRequest::new(just_inside).is_ok());

    let just_outside = (0..=MAX_HISTORY_UPDATE_ENTRIES)
        .map(|index| HistoryEntryUpdate::new(format!("entry-{index}")).expect("valid"))
        .collect::<Vec<_>>();
    assert!(matches!(
        UpdateHistoryEntriesRequest::new(just_outside),
        Err(Error::Validation {
            field: "entries",
            ..
        })
    ));

    assert!(matches!(
        HistoryEntryUpdate::new(""),
        Err(Error::Validation { field: "id", .. })
    ));
    assert!(matches!(
        DeleteHistoryEntriesRequest::new(Vec::<String>::new()),
        Err(Error::Validation { field: "id", .. })
    ));
    assert!(matches!(
        DeleteHistoryEntriesRequest::new(["100001234".to_string(), "100001234".to_string(),]),
        Err(Error::Validation { field: "id", .. })
    ));
    assert!(matches!(
        DeleteHistoryEntriesRequest::new(["../history".to_string()]),
        Err(Error::Validation { field: "id", .. })
    ));
}

#[test]
fn history_note_update_and_response_helpers_cover_empty_and_unknown_values() {
    let mut request = UpdateHistoryEntryRequest::new();
    request.note = Some(String::new());
    assert_eq!(request.to_json(), serde_json::json!({"note": ""}));
    assert!(matches!(
        SetHistoryEntryNoteRequest::new(""),
        Err(Error::Validation { field: "note", .. })
    ));
    assert_eq!(
        HistoryEntryKind::from_wire("page"),
        HistoryEntryKind::Other("page".to_string())
    );
    assert_eq!(
        HistoryDirection::from_wire("sideways"),
        HistoryDirection::Other("sideways".to_string())
    );
    assert_eq!(
        HistoryStarred::from_wire("tomorrow"),
        HistoryStarred::Other("tomorrow".to_string())
    );
}

#[tokio::test]
async fn the_base_url_and_timeout_are_configurable() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = RestClient::new(transport.clone(), static_auth())
        .with_base_url("http://localhost:8080/")
        .with_timeout(Some(Duration::from_millis(1500)));

    client.hangup("c1").await.expect("hung up");
    let call = transport.only_call();
    assert_eq!(call.url, "http://localhost:8080/v2/calls/c1");
    // The per-request timeout is now a budget: the attempt is handed what is
    // left of it, which is at most the configured value.
    let timeout = call.timeout.expect("timeout applied");
    assert!(
        timeout <= Duration::from_millis(1500),
        "attempt exceeded the configured timeout: {timeout:?}"
    );
    assert!(
        timeout > Duration::from_millis(1400),
        "attempt was handed a drastically short budget: {timeout:?}"
    );
}

#[tokio::test]
async fn a_429_is_retried_after_the_retry_after_delay() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(429, &[("Retry-After", "1")], b"slow down"));
    transport.push_response(no_content());

    client.hangup("c1").await.expect("second attempt wins");
    assert_eq!(transport.call_count(), 2);
    assert_eq!(sleeper.delays(), [Duration::from_secs(1)]);
}

#[tokio::test]
async fn retry_after_is_clamped_to_the_ceiling() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(429, &[("Retry-After", "600")], b"slow down"));
    transport.push_response(no_content());

    client.hangup("c1").await.expect("retried");
    assert_eq!(sleeper.delays(), [Duration::from_secs(8)]);
}

#[tokio::test]
async fn a_server_without_retry_after_falls_back_to_doubling_backoff() {
    let (transport, sleeper, client) = harness();
    for _ in 0..2 {
        transport.push_response(response(503, &[], b"maintenance"));
    }
    transport.push_response(no_content());

    client.hangup("c1").await.expect("third attempt wins");
    let delays = sleeper.delays();
    assert_eq!(delays.len(), 2);
    assert!(delays[0] >= Duration::from_millis(125));
    assert!(delays[0] <= Duration::from_millis(250));
    assert!(delays[1] >= Duration::from_millis(250));
    assert!(delays[1] <= Duration::from_millis(500));
    assert_eq!(transport.call_count(), 3);
}

#[tokio::test]
async fn a_persistent_5xx_spends_the_budget_and_surfaces_the_error() {
    let (transport, sleeper, client) = harness();
    for _ in 0..10 {
        transport.push_response(response(500, &[], b"boom"));
    }

    let error = client.hangup("c1").await.expect_err("exhausted");
    assert!(matches!(error, Error::Api { status: 500, .. }));
    assert_eq!(transport.call_count(), 3, "max_attempts is 3");
    let delays = sleeper.delays();
    assert_eq!(delays.len(), 2);
    assert!(delays[0] >= Duration::from_millis(125));
    assert!(delays[0] <= Duration::from_millis(250));
    assert!(delays[1] >= Duration::from_millis(250));
    assert!(delays[1] <= Duration::from_millis(500));
    assert!(sleeper.total() >= Duration::from_millis(375));
    assert!(sleeper.total() <= Duration::from_millis(750));
}

#[tokio::test]
async fn a_no_retry_policy_stops_after_the_first_failure() {
    let transport = MockTransport::new();
    transport.push_response(response(503, &[], b"maintenance"));
    let client = RestClient::new(transport.clone(), static_auth())
        .with_sleeper(RecordingSleeper::new())
        .with_retry(RetryPolicy::none());

    assert!(client.hangup("c1").await.is_err());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_4xx_that_is_not_401_is_terminal() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(404, &[], b"{\"error\":\"call not found\"}"));

    let error = client.hangup("c1").await.expect_err("404");
    assert!(matches!(error, Error::Api { status: 404, .. }));
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
    assert_eq!(sleeper.delays().len(), 0);
}

#[tokio::test]
async fn an_error_body_is_truncated_for_logs() {
    let (transport, _, client) = harness();
    let huge = "x".repeat(10_000);
    transport.push_response(response(400, &[], huge.as_bytes()));
    let error = client.hangup("c1").await.expect_err("400");
    let rendered = format!("{error}");
    assert!(
        rendered.len() < 1000,
        "body not truncated: {}",
        rendered.len()
    );
}

#[tokio::test]
async fn a_transient_transport_failure_is_retried_and_a_terminal_one_is_not() {
    let (transport, _, client) = harness();
    transport.push_transient_failure("connect: connection refused");
    transport.push_response(no_content());
    client.hangup("c1").await.expect("retried");
    assert_eq!(transport.call_count(), 2);

    let (transport, _, client) = harness();
    transport.push_terminal_failure("unsupported scheme");
    let error = client.hangup("c1").await.expect_err("terminal");
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

/// A token source that hands out `t1`, `t2`, … and records every force flag.
struct RotatingToken {
    issued: AtomicUsize,
    forced: Mutex<Vec<bool>>,
}

impl RotatingToken {
    fn new() -> Self {
        Self {
            issued: AtomicUsize::new(0),
            forced: Mutex::new(Vec::new()),
        }
    }

    fn forced(&self) -> Vec<bool> {
        self.forced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl TokenSource for RotatingToken {
    fn refreshable(&self) -> bool {
        true
    }

    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.forced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(force_refresh);
        let issued = self.issued.fetch_add(1, Ordering::Relaxed) + 1;
        std::future::ready(Token::from_json(
            &serde_json::json!({"access_token": format!("t{issued}")}),
        ))
    }

    fn invalidate(&self) {}
}

#[tokio::test]
async fn a_401_refreshes_once_and_then_succeeds() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(no_content());
    let sleeper = RecordingSleeper::new();
    let client =
        RestClient::new(transport.clone(), RotatingToken::new()).with_sleeper(sleeper.clone());

    client.hangup("c1").await.expect("refresh worked");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].auth.bearer(), Some("t1"));
    assert_eq!(calls[1].auth.bearer(), Some("t2"), "second token used");
    // The resend is paced through the same policy as any other retry, so a
    // burst of 401s cannot hammer the API or the token endpoint.
    let delays = sleeper.delays();
    assert_eq!(delays.len(), 1, "the single resend is paced exactly once");
    assert!(delays[0] >= Duration::from_millis(125));
    assert!(delays[0] <= Duration::from_millis(250));
}

#[tokio::test]
async fn the_401_resend_obeys_the_retry_policy_ceiling() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[("Retry-After", "600")], b"expired"));
    transport.push_response(no_content());
    let sleeper = RecordingSleeper::new();
    let client = RestClient::new(transport.clone(), RotatingToken::new())
        .with_sleeper(sleeper.clone())
        .with_retry(RetryPolicy::default().with_max_delay(Duration::from_secs(2)));

    client.hangup("c1").await.expect("refresh worked");
    assert_eq!(transport.call_count(), 2);
    // A hostile `Retry-After` is clamped to the policy ceiling, exactly as it
    // is on every other retry path.
    assert_eq!(sleeper.delays(), [Duration::from_secs(2)]);
}

#[tokio::test]
async fn the_two_401_attempts_share_the_caller_timeout_budget() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(no_content());
    let budget = Duration::from_secs(10);
    let client = RestClient::new(transport.clone(), RotatingToken::new())
        .with_sleeper(RecordingSleeper::new())
        .with_timeout(Some(budget));

    client.hangup("c1").await.expect("refresh worked");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    // Each attempt is handed only what is left of the one deadline, never a
    // fresh full timeout, so the two attempts together stay inside the budget.
    let first = calls[0]
        .timeout
        .expect("budget applied to the first attempt");
    let second = calls[1]
        .timeout
        .expect("budget applied to the second attempt");
    assert!(
        first <= budget,
        "first attempt exceeded the budget: {first:?}"
    );
    assert!(
        second <= budget,
        "second attempt got a fresh budget: {second:?}"
    );
    // The deadline only ever drains, so the resend can never be handed more
    // time than the attempt that went before it.
    assert!(
        second <= first,
        "the budget grew between attempts: {first:?} -> {second:?}"
    );
}

#[tokio::test]
async fn a_second_401_is_terminal() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"no"));
    transport.push_response(response(
        401,
        &[("Retry-After", "11"), ("X-Request-ID", "req-second-401")],
        b"still no",
    ));
    let client = RestClient::new(transport.clone(), RotatingToken::new())
        .with_sleeper(RecordingSleeper::new());

    let error = client.hangup("c1").await.expect_err("terminal");
    assert!(matches!(
        error,
        Error::Unauthorized {
            status: 401,
            ref body,
            retry_after: Some(retry_after),
            request_id: Some(ref request_id),
            ..
        } if body == b"still no"
            && retry_after == Duration::from_secs(11)
            && request_id == "req-second-401"
    ));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(11)));
    assert_eq!(transport.call_count(), 2, "refresh once, never loop");
}

#[tokio::test]
async fn the_refresh_is_requested_forcefully() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(no_content());
    let auth = Arc::new(RotatingToken::new());
    let client = RestClient::new(transport, AuthHandle(Arc::clone(&auth)))
        .with_sleeper(RecordingSleeper::new());

    client.hangup("c1").await.expect("ok");
    assert_eq!(auth.forced(), [false, true]);
}

#[derive(Clone)]
struct SlowTokenEndpoint {
    api: MockTransport,
    token: MockTransport,
    api_started: Arc<AtomicUsize>,
    token_started: Arc<AtomicBool>,
    release_api: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    refreshed: Arc<AtomicBool>,
}

impl SlowTokenEndpoint {
    fn new() -> Self {
        Self {
            api: MockTransport::new(),
            token: MockTransport::new(),
            api_started: Arc::new(AtomicUsize::new(0)),
            token_started: Arc::new(AtomicBool::new(false)),
            release_api: Arc::new(AtomicBool::new(false)),
            release: Arc::new(AtomicBool::new(false)),
            refreshed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl sipgate_flow::Transport for SlowTokenEndpoint {
    async fn execute(
        &self,
        request: sipgate_flow::transport::Request<'_>,
    ) -> Result<sipgate_flow::transport::Response> {
        if request.url == sipgate_flow::auth::DEFAULT_TOKEN_URL {
            self.token_started.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            return self.token.execute(request).await;
        }
        let attempt = self.api_started.fetch_add(1, Ordering::SeqCst);
        if attempt >= 8 {
            while !self.refreshed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            self.api.execute(request).await?;
            return Ok(response(200, &[], b"{}"));
        }
        while !self.release_api.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        self.api.execute(request).await?;
        Ok(response(401, &[], b"expired"))
    }
}

impl SlowTokenEndpoint {
    fn api_calls(&self) -> Vec<common::Call> {
        self.api.calls()
    }

    fn api_started(&self) -> usize {
        self.api_started.load(Ordering::SeqCst)
    }

    fn token_calls(&self) -> Vec<common::Call> {
        self.token.calls()
    }
}

struct OAuthHandle(Arc<OAuth2Client<SlowTokenEndpoint>>);

impl TokenSource for OAuthHandle {
    fn refreshable(&self) -> bool {
        self.0.refreshable()
    }

    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.0.access_token(force_refresh)
    }

    fn refresh_after(
        &self,
        stale: &Token,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.0.refresh_after(stale)
    }

    fn invalidate(&self) {
        self.0.invalidate();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_401s_trigger_one_single_flight_token_refresh() {
    let transport = SlowTokenEndpoint::new();
    for token in ["stale", "fresh"] {
        transport
            .token
            .push_response(json_response(&serde_json::json!({
                "access_token": token,
                "expires_in": 300,
            })));
    }
    transport.release.store(true, Ordering::SeqCst);
    let auth = Arc::new(
        OAuth2Client::new(
            transport.clone(),
            ClientCredentials::new("client-id", "hunter2").expect("credentials"),
        )
        .with_token_url(sipgate_flow::auth::DEFAULT_TOKEN_URL),
    );
    let stale = auth.access_token(false).await.expect("cached stale token");
    assert_eq!(stale.access_token(), "stale");
    let token_calls_before_refresh = transport.token_calls().len();
    transport.release.store(false, Ordering::SeqCst);
    transport.token_started.store(false, Ordering::SeqCst);
    transport.api_started.store(0, Ordering::SeqCst);
    transport.release_api.store(false, Ordering::SeqCst);
    transport.refreshed.store(false, Ordering::SeqCst);
    let client = Arc::new(
        RestClient::new(transport.clone(), OAuthHandle(auth)).with_sleeper(RecordingSleeper::new()),
    );

    let mut handles = Vec::new();
    for task in 0..8 {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            client.hangup(&format!("call-{task}")).await
        }));
    }
    while transport.api_started.load(Ordering::SeqCst) < 8 {
        tokio::task::yield_now().await;
    }
    transport.release_api.store(true, Ordering::SeqCst);
    for _ in 0..10_000 {
        if transport.token_started.load(Ordering::SeqCst) || transport.api_started() >= 16 {
            break;
        }
        tokio::task::yield_now().await;
    }
    transport.release.store(true, Ordering::SeqCst);
    transport.refreshed.store(true, Ordering::SeqCst);
    for handle in handles {
        handle.await.expect("task").expect("hung up");
    }

    assert_eq!(
        transport.token_calls().len(),
        token_calls_before_refresh + 1,
        "one token POST for all concurrent 401s"
    );
    assert_eq!(transport.api_calls().len(), 16);
}

/// A newtype so the test can keep a handle on the same token source.
struct AuthHandle(Arc<RotatingToken>);

impl TokenSource for AuthHandle {
    fn refreshable(&self) -> bool {
        self.0.refreshable()
    }

    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.0.access_token(force_refresh)
    }

    fn invalidate(&self) {}
}

#[test]
fn the_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TestClient>();
    assert_send_sync::<RestClient<MockTransport, RotatingToken, RecordingSleeper>>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_tasks_hammer_one_client() {
    let transport = MockTransport::always(no_content());
    let client = Arc::new(
        RestClient::new(transport.clone(), static_auth()).with_sleeper(RecordingSleeper::new()),
    );

    let mut handles = Vec::new();
    for task in 0..32 {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            for round in 0..8 {
                client
                    .hangup(&format!("call-{task}-{round}"))
                    .await
                    .expect("hung up");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task");
    }
    assert_eq!(transport.call_count(), 32 * 8);
}

#[tokio::test]
async fn a_custom_retry_policy_is_honoured() {
    let (transport, sleeper, client) = harness();
    for _ in 0..5 {
        transport.push_response(response(502, &[], b"bad gateway"));
    }
    let client = client.with_retry(Policy::new(5).with_base_delay(Duration::from_secs(1)));

    let error = client.hangup("c1").await.expect_err("exhausted");
    assert!(matches!(error, Error::Api { status: 502, .. }));
    assert_eq!(transport.call_count(), 5);
    let delays = sleeper.delays();
    assert_eq!(delays.len(), 4);
    for (index, delay) in delays.into_iter().enumerate() {
        let exponent = u32::try_from(index).unwrap_or_default();
        let high = Duration::from_secs(1_u64 << exponent);
        assert!(delay >= high / 2);
        assert!(delay <= high);
    }
}

#[test]
fn the_documented_host_and_base_path_are_exported() {
    assert_eq!(
        sipgate_flow::rest::DEFAULT_BASE_URL,
        "https://api.sipgate.com"
    );
    assert_eq!(sipgate_flow::rest::BASE_PATH, "/v2");
    assert_eq!(sipgate_flow::rest::MAX_FAX_BASE64_LEN, 28_330_000);
}

#[test]
fn sms_keeps_the_plus_prefix_the_schema_shows() {
    let sms = Sms::new("s0", "4915112345678", "hi").expect("valid");
    assert_eq!(sms.recipient(), "+4915112345678");
    assert_eq!(sms.to_json()["recipient"], "+4915112345678");
    let scheduled = Sms::new("s0", "4915112345678", "hi")
        .expect("valid")
        .with_send_at(1_546_850_272);
    assert_eq!(scheduled.to_json()["sendAt"], 1_546_850_272_i64);
}

#[test]
fn fax_refuses_an_empty_line_a_relative_name_and_bad_base64() {
    assert!(Fax::new("", "4915112345678", "a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "dir/a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "dir\\a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "a.pdf", "not base64").is_err());
    assert!(Fax::new("f0", "4915112345678", "", "JVBERi0=").is_err());
    let fax = Fax::new("f0", "+4915112345678", "a.pdf", "JVBERi0=").expect("valid");
    assert_eq!(fax.content(), "JVBERi0=");
    assert_eq!(fax.to_json()["recipient"], "+4915112345678");
}

#[test]
fn sms_request_fields_are_bounded_before_the_body_is_built() {
    assert!(Sms::new("s0", "4915112345678", "x").is_ok());
    assert!(Sms::new("s0", "4915112345678", "x".repeat(1024 * 1024)).is_ok());
    assert!(Sms::new("s0", "4915112345678", "x".repeat(1024 * 1024 + 1)).is_err());
}

#[test]
fn fax_request_identifiers_are_bounded_before_the_body_is_built() {
    assert!(Fax::new("f0", "4915112345678", "fax.pdf", "JVBERi0=").is_ok());
    let limit = 1024 * 1024;
    assert!(Fax::new("s".repeat(limit), "4915112345678", "fax.pdf", "JVBERi0=").is_ok());
    assert!(Fax::new(
        "s".repeat(limit + 1),
        "4915112345678",
        "fax.pdf",
        "JVBERi0="
    )
    .is_err());
    assert!(Fax::new("f0", "4915112345678", "f".repeat(limit), "JVBERi0=").is_ok());
    assert!(Fax::new("f0", "4915112345678", "f".repeat(limit + 1), "JVBERi0=").is_err());
}

#[test]
fn dtmf_and_call_identifiers_are_bounded_before_the_body_is_built() {
    let limit = 1024 * 1024;
    assert!(Dtmf::new("1").is_ok());
    assert!(Dtmf::new("1".repeat(limit)).is_ok());
    assert!(Dtmf::new("1".repeat(limit + 1)).is_err());
    assert!(Call::new("e0", "4915112345678").is_ok());
    assert!(Call::new("e".repeat(limit), "4915112345678").is_ok());
    assert!(Call::new("e".repeat(limit + 1), "4915112345678").is_err());
}

#[test]
fn resend_fax_omits_an_unset_line() {
    assert!(ResendFax::new("1").to_json().get("faxlineId").is_none());
    assert_eq!(
        ResendFax::new("1").with_faxline_id("f0").to_json()["faxlineId"],
        "f0"
    );
}

#[test]
fn call_builders_render_the_optional_fields() {
    let call = Call::new("4915112345678", "4921112345678")
        .expect("valid")
        .with_caller_id("+4930112345678")
        .expect("valid")
        .with_device_id("e0");
    let body = call.to_json();
    assert_eq!(body["caller"], "4915112345678");
    assert_eq!(body["callerId"], "+4930112345678");
    assert_eq!(body["deviceId"], "e0");

    assert!(Call::new("4915112345678", "4921112345678")
        .expect("valid")
        .with_caller_id("nope")
        .is_err());
}

#[test]
fn channel_call_builders_render_the_optional_fields() {
    let call = ChannelCall::new("e0", "667")
        .with_caller_id("49211")
        .with_channel_id("c0");
    let body = call.to_json();
    assert_eq!(body["callerId"], "49211");
    assert_eq!(body["channelId"], "c0");
    // An internal extension is a legal target and stays unvalidated.
    assert_eq!(body["targetNumber"], "667");
}

#[test]
fn dtmf_rejects_characters_outside_the_alphabet() {
    assert!(Dtmf::new("1234567890*#ABCD").is_ok());
    for bad in ["12x4", "12 34", "abc", "ä"] {
        assert!(Dtmf::new(bad).is_err(), "{bad:?}");
    }
    assert_eq!(Dtmf::new("1234").expect("valid").sequence(), "1234");
}

#[test]
fn announcements_must_be_absolute_http_urls() {
    assert!(Announcement::new("http://x").is_ok());
    assert!(Announcement::new("https://x.test/a.wav").is_ok());
    assert!(Announcement::new("https://x.test/a.wav?cache=1#frag").is_ok());
    assert!(Announcement::new("HTTPS://x.test/a.wav").is_ok());
    for bad in [
        "",
        "x.test/a.wav",
        "/a.wav",
        "file:///etc/passwd",
        "https://",
        "https:///path",
        "https://:8080",
        "http://?x=1",
        "https://#frag",
        "https://@x.test/a.wav",
        "https://user:pw@x.test/a.wav",
        "https://x.test/a b.wav",
        "https://x.test/a\n.wav",
        "https://x.test/a\u{0}.wav",
        "https://x.test/a\u{1}.wav",
        "https://x.test/a\u{7f}.wav",
    ] {
        assert!(Announcement::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn recording_renders_start_stop_and_the_announcement_flag() {
    assert!(Recording::start().is_starting());
    assert!(!Recording::stop().is_starting());
    assert_eq!(Recording::stop().to_json()["value"], false);
    let silent = Recording::start().with_announcement(false);
    assert_eq!(silent.to_json()["announcement"], false);
    assert!(Recording::start().to_json().get("announcement").is_none());
}

#[test]
fn transfer_request_supports_blind_attended_and_a_caller_id() {
    let blind = TransferRequest::blind("4915112345678").expect("valid");
    assert_eq!(blind.to_json()["attended"], false);
    let attended = TransferRequest::attended("4915112345678").expect("valid");
    assert_eq!(attended.to_json()["attended"], true);
    let with_id = TransferRequest::blind("4915112345678")
        .expect("valid")
        .with_caller_id("4921112345678")
        .expect("valid");
    assert_eq!(with_id.to_json()["callerId"], "+4921112345678");
    assert!(TransferRequest::blind("no").is_err());
    assert!(TransferRequest::blind("4915112345678")
        .expect("valid")
        .with_caller_id("no")
        .is_err());
}

#[test]
fn recording_session_renders_every_field_it_has() {
    let request = RecordingSession::new()
        .with_device_id("e0")
        .with_endpoint("MAIN")
        .with_target_id("v0");
    assert_eq!(
        request.to_json(),
        serde_json::json!({"deviceId": "e0", "endpoint": "MAIN", "targetId": "v0"})
    );
    assert_eq!(RecordingSession::new().to_json(), serde_json::json!({}));
}

#[test]
fn voicemail_playback_exposes_both_fields() {
    let request = PlayVoicemail::new("1000171", "e0");
    assert_eq!(request.to_json()["datadId"], "1000171");
    assert_eq!(request.to_json()["deviceId"], "e0");
}

#[tokio::test]
async fn an_unexpected_call_list_envelope_is_a_typed_error() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"data": "nope"})));
    let client = RestClient::new(transport, static_auth()).with_sleeper(RecordingSleeper::new());
    let error = client.calls().await.expect_err("wrong shape");
    assert!(matches!(error, Error::Json { .. }));
}

#[tokio::test]
async fn a_call_without_participants_still_parses() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "data": [{
            "callId": "c1", "hold": true, "muted": false, "recording": false,
            "participants": [], "future": {"x": 1}
        }]
    })));
    let client = RestClient::new(transport, static_auth()).with_sleeper(RecordingSleeper::new());
    let calls = client.calls().await.expect("listed");
    assert_eq!(calls[0].call_id, "c1");
    assert!(calls[0].hold);
    assert_eq!(calls[0].participants.len(), 0);
}

// ===================================================================
// Issue #164 — REST v2 `devices` resource. Self-contained so the sibling
// resource PRs can each add their own block without conflicts.
// ===================================================================
mod devices_164 {
    use super::*;
    use sipgate_flow::rest::{
        ActivateSim, ChangeDevice, Contingent, CreateDevice, CreateExternalDevice,
        CreateMobileDevice, CreateRegisterDevice, DeviceAlias, DeviceCallerId, DeviceContingents,
        DeviceFilter, DeviceKind, DevicePassword, ExternalDevice, ExternalTargetNumber,
        IncomingCallDisplay, Localprefix, MobileCredentials, MobileDevice, OrderSim,
        RegisterCredentials, RegisterDevice, RegisteredEndpoint, SimState, SingleRowDisplay,
        TariffAnnouncement,
    };

    #[tokio::test]
    async fn list_devices_filters_by_type_in_the_query() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "items": [{"id": "e0", "alias": "Desk", "type": "REGISTER", "futureField": 1}]
        })));
        let devices = client
            .user_devices("w0", &[DeviceFilter::Register, DeviceFilter::Mobile])
            .await
            .expect("listed");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "e0");
        assert_eq!(devices[0].kind, Some(DeviceKind::Register));

        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "GET");
        assert_eq!(
            call.url,
            "https://api.sipgate.com/v2/w0/devices?type=register,mobile"
        );
        assert_eq!(call.body, Body::Empty);
    }

    #[tokio::test]
    async fn list_devices_without_filter_omits_the_query() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"items": []})));
        assert_eq!(client.user_devices("w0", &[]).await.expect("listed"), []);
        assert_eq!(
            transport.only_call().url,
            "https://api.sipgate.com/v2/w0/devices"
        );
    }

    #[tokio::test]
    async fn list_devices_refuses_an_undocumented_filter() {
        let (transport, _, client) = harness();
        let error = client
            .user_devices("w0", &[DeviceFilter::Other("future".into())])
            .await
            .expect_err("undocumented filter");
        assert!(matches!(error, Error::Validation { field: "type", .. }));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn create_update_delete_hit_the_documented_paths_and_bodies() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "id": "e0", "alias": "Desk", "type": "REGISTER"
        })));
        transport.push_response(no_content());
        transport.push_response(no_content());
        transport.push_response(no_content());

        let created = client
            .create_device(
                "w0",
                &CreateDevice::new(DeviceKind::Register)
                    .unwrap()
                    .with_alias("Desk")
                    .unwrap(),
            )
            .await
            .expect("created");
        assert_eq!(created.id, "e0");

        client
            .update_device(
                "e0",
                &ChangeDevice::new()
                    .with_dnd(true)
                    .with_emergency_address_id(42),
            )
            .await
            .expect("updated");
        client
            .update_device_alias("e0", &DeviceAlias::new("New name").expect("alias"))
            .await
            .expect("renamed");
        client.delete_device("e0").await.expect("deleted");

        let calls = transport.calls();
        assert_eq!(calls[0].method.as_str(), "POST");
        assert_eq!(calls[0].url, "https://api.sipgate.com/v2/w0/devices");
        assert_eq!(
            json_body(&calls[0].body),
            serde_json::json!({"type": "register", "alias": "Desk"})
        );
        assert_eq!(calls[1].method.as_str(), "PUT");
        assert_eq!(calls[1].url, "https://api.sipgate.com/v2/devices/e0");
        assert_eq!(
            json_body(&calls[1].body),
            serde_json::json!({"dnd": true, "emergencyAddressId": 42})
        );
        assert_eq!(calls[2].url, "https://api.sipgate.com/v2/devices/e0/alias");
        assert_eq!(
            json_body(&calls[2].body),
            serde_json::json!({"value": "New name"})
        );
        assert_eq!(calls[3].method.as_str(), "DELETE");
        assert_eq!(calls[3].url, "https://api.sipgate.com/v2/devices/e0");
        assert_eq!(calls[3].body, Body::Empty);
    }

    #[tokio::test]
    async fn create_kind_specific_devices_decode_their_responses() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "id": "x0", "alias": "Home", "number": "+4915112345678",
            "incomingCallDisplayState": "CALLER_NUMBER"
        })));
        transport.push_response(json_response(&serde_json::json!({
            "id": "m0", "esim": true, "simState": "ACTIVE",
            "credentials": {"simId": "1234567", "puk1": "1", "puk2": "2"}
        })));
        transport.push_response(json_response(&serde_json::json!({
            "id": "e0", "addressUrl": "/addresses/1", "emergencyAddressId": "1",
            "registered": [{"ip": "10.0.0.1", "port": "5060", "userAgent": "ua"}],
            "credentials": {"username": "u", "sipServer": "sip.example"}
        })));

        let external: ExternalDevice = client
            .create_external_device(
                "w0",
                &CreateExternalDevice::new("4915112345678").expect("number"),
            )
            .await
            .expect("external");
        assert_eq!(
            external.incoming_call_display,
            Some(IncomingCallDisplay::CallerNumber)
        );
        assert_eq!(external.number, "+4915112345678");

        let mobile: MobileDevice = client
            .create_mobile_device("w0", &CreateMobileDevice::new())
            .await
            .expect("mobile");
        assert!(mobile.esim);
        assert_eq!(mobile.sim_state, Some(SimState::Active));
        assert_eq!(
            mobile.credentials.as_ref().map(|c| c.sim_id.as_str()),
            Some("1234567")
        );

        let registered: RegisterDevice = client
            .create_register_device("w0", &CreateRegisterDevice::new())
            .await
            .expect("registered");
        assert_eq!(registered.registered[0].port, "5060");
        assert_eq!(
            registered
                .credentials
                .as_ref()
                .map(|c| c.sip_server.as_str()),
            Some("sip.example")
        );

        let calls = transport.calls();
        assert_eq!(
            calls[0].url,
            "https://api.sipgate.com/v2/w0/devices/external"
        );
        assert_eq!(calls[1].url, "https://api.sipgate.com/v2/w0/devices/mobile");
        assert_eq!(
            calls[2].url,
            "https://api.sipgate.com/v2/w0/devices/register"
        );
        for call in calls {
            assert_eq!(call.method.as_str(), "POST");
            assert_eq!(call.auth.bearer(), Some("access-token"));
        }
    }

    #[tokio::test]
    async fn caller_id_and_password_endpoints_round_trip() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(
            &serde_json::json!({"value": "+4915112345678"}),
        ));
        transport.push_response(no_content());
        transport.push_response(json_response(&serde_json::json!({"password": "generated"})));

        let caller_id = client.device_caller_id("e0").await.expect("read");
        assert_eq!(caller_id.value, "+4915112345678");
        client
            .update_device_caller_id("e0", &DeviceCallerId::new("4915112345678").expect("number"))
            .await
            .expect("written");
        let rotated = client.reset_device_password("e0").await.expect("reset");
        assert_eq!(rotated.password, "generated");

        let calls = transport.calls();
        assert_eq!(calls[0].method.as_str(), "GET");
        assert_eq!(
            calls[0].url,
            "https://api.sipgate.com/v2/devices/e0/callerid"
        );
        assert_eq!(calls[1].method.as_str(), "PUT");
        assert_eq!(
            json_body(&calls[1].body),
            serde_json::json!({"value": "+4915112345678"})
        );
        assert_eq!(calls[2].method.as_str(), "POST");
        assert_eq!(
            calls[2].url,
            "https://api.sipgate.com/v2/devices/e0/credentials/password"
        );
    }

    #[tokio::test]
    async fn external_settings_and_display_and_settings_endpoints() {
        let (transport, _, client) = harness();
        for _ in 0..5 {
            transport.push_response(no_content());
        }
        transport.push_response(json_response(
            &serde_json::json!({"active": true, "value": "030"}),
        ));
        transport.push_response(json_response(&serde_json::json!({"enabled": true})));
        transport.push_response(json_response(&serde_json::json!({"enabled": false})));

        client
            .update_external_incoming_call_display("x0", IncomingCallDisplay::CalledNumber)
            .await
            .expect("display");
        client
            .update_external_target_number(
                "x0",
                &ExternalTargetNumber::new("4915112345678").expect("number"),
            )
            .await
            .expect("target");
        client
            .update_device_localprefix("e0", &Localprefix::new(true, "030").expect("prefix"))
            .await
            .expect("prefix set");
        client
            .update_device_single_row_display("e0", &SingleRowDisplay::new(true))
            .await
            .expect("single row");
        client
            .update_device_tariff_announcement("e0", &TariffAnnouncement::new(true))
            .await
            .expect("tariff");

        let prefix: Localprefix = client.device_localprefix("e0").await.expect("read prefix");
        assert_eq!(prefix.value, "030");
        let single: SingleRowDisplay = client
            .device_single_row_display("e0")
            .await
            .expect("read single");
        assert!(single.enabled);
        let tariff: TariffAnnouncement = client
            .device_tariff_announcement("e0")
            .await
            .expect("read tariff");
        assert!(!tariff.enabled);

        let calls = transport.calls();
        assert_eq!(
            calls[0].url,
            "https://api.sipgate.com/v2/devices/x0/external/incomingcalldisplay"
        );
        assert_eq!(
            json_body(&calls[0].body),
            serde_json::json!({"incomingCallDisplay": "CALLED_NUMBER"})
        );
        assert_eq!(
            calls[1].url,
            "https://api.sipgate.com/v2/devices/x0/external/targetnumber"
        );
        assert_eq!(
            json_body(&calls[1].body),
            serde_json::json!({"number": "+4915112345678"})
        );
        assert_eq!(
            calls[2].url,
            "https://api.sipgate.com/v2/devices/e0/localprefix"
        );
        assert_eq!(
            json_body(&calls[2].body),
            serde_json::json!({"active": true, "value": "030"})
        );
        assert_eq!(
            calls[4].url,
            "https://api.sipgate.com/v2/devices/e0/tariffannouncement"
        );
    }

    #[tokio::test]
    async fn contingents_and_sim_operations_hit_their_paths() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "contingents": [{
                "type": "DATA_FAST", "amount": 2500, "used": 1000, "left": 1500,
                "unit": "KILOBYTE", "expires": "2016-02-10T14:19:39Z"
            }]
        })));
        transport.push_response(no_content());
        transport.push_response(no_content());
        transport.push_response(no_content());

        let contingents: DeviceContingents = client
            .device_contingents("w0", "y0")
            .await
            .expect("contingents");
        assert_eq!(contingents.contingents[0].left, 1500);
        client.deactivate_sim("w0", "y0").await.expect("deactivate");
        client
            .activate_sim("w0", "y0", &ActivateSim::new("1234567").expect("sim"))
            .await
            .expect("activate");
        client
            .order_sim("w0", "y0", &OrderSim::new("123456").expect("address"))
            .await
            .expect("order");

        let calls = transport.calls();
        assert_eq!(
            calls[0].url,
            "https://api.sipgate.com/v2/w0/devices/y0/contingents"
        );
        assert_eq!(calls[1].method.as_str(), "DELETE");
        assert_eq!(calls[1].url, "https://api.sipgate.com/v2/w0/devices/y0/sim");
        assert_eq!(
            json_body(&calls[2].body),
            serde_json::json!({"simId": "1234567"})
        );
        assert_eq!(
            calls[3].url,
            "https://api.sipgate.com/v2/w0/devices/y0/sim/orders"
        );
        assert_eq!(
            json_body(&calls[3].body),
            serde_json::json!({"addressId": "123456"})
        );
    }

    #[tokio::test]
    async fn per_endpoint_id_parameters_are_validated_before_the_wire() {
        let (transport, _, client) = harness();
        for bad in ["", ".", "..", "a/b", "a?b", "a b", "a#b"] {
            assert!(matches!(
                client.delete_device(bad).await.expect_err("bad device"),
                Error::Validation {
                    field: "device_id",
                    ..
                }
            ));
            assert!(matches!(
                client.user_devices(bad, &[]).await.expect_err("bad user"),
                Error::Validation {
                    field: "user_id",
                    ..
                }
            ));
            assert!(matches!(
                client
                    .device_contingents("w0", bad)
                    .await
                    .expect_err("bad device"),
                Error::Validation {
                    field: "device_id",
                    ..
                }
            ));
            assert!(matches!(
                client
                    .deactivate_sim("w0", bad)
                    .await
                    .expect_err("bad device"),
                Error::Validation {
                    field: "device_id",
                    ..
                }
            ));
            assert!(matches!(
                client
                    .device_contingents(bad, "y0")
                    .await
                    .expect_err("bad user"),
                Error::Validation {
                    field: "user_id",
                    ..
                }
            ));
        }
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn every_path_boundary_accepts_just_inside_and_rejects_just_outside() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"items": []})));
        transport.push_response(json_response(&serde_json::json!({"items": []})));

        let inside = "a".repeat(200);
        let outside = "a".repeat(201);
        assert!(client.user_devices(&inside, &[]).await.is_ok());
        assert!(matches!(
            client.user_devices(&outside, &[]).await,
            Err(Error::Validation {
                field: "user_id",
                ..
            })
        ));
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn request_field_boundaries_accept_just_inside_and_reject_just_outside() {
        // `validate::MAX_REST_FIELD_BYTES` is the documented 1 MiB ceiling.
        let limit = 1024 * 1024;

        assert!(DeviceAlias::new("a".repeat(limit)).is_ok());
        assert!(matches!(
            DeviceAlias::new("a".repeat(limit + 1)),
            Err(Error::Validation { field: "value", .. })
        ));

        assert!(CreateDevice::new(DeviceKind::Register)
            .unwrap()
            .with_alias("a".repeat(limit))
            .is_ok());
        assert!(matches!(
            CreateDevice::new(DeviceKind::Register)
                .unwrap()
                .with_alias("a".repeat(limit + 1)),
            Err(Error::Validation { field: "alias", .. })
        ));

        assert!(CreateMobileDevice::new()
            .with_alias("a".repeat(limit))
            .is_ok());
        assert!(matches!(
            CreateMobileDevice::new().with_alias("a".repeat(limit + 1)),
            Err(Error::Validation { field: "alias", .. })
        ));
        assert!(CreateRegisterDevice::new()
            .with_alias("a".repeat(limit))
            .is_ok());
        assert!(matches!(
            CreateRegisterDevice::new().with_alias("a".repeat(limit + 1)),
            Err(Error::Validation { field: "alias", .. })
        ));
        assert!(CreateExternalDevice::new("4915112345678")
            .unwrap()
            .with_alias("a".repeat(limit))
            .is_ok());
        assert!(matches!(
            CreateExternalDevice::new("4915112345678")
                .unwrap()
                .with_alias("a".repeat(limit + 1)),
            Err(Error::Validation { field: "alias", .. })
        ));

        assert!(ActivateSim::new("a".repeat(limit)).is_ok());
        assert!(matches!(
            ActivateSim::new("a".repeat(limit + 1)),
            Err(Error::Validation {
                field: "sim_id",
                ..
            })
        ));
        assert!(OrderSim::new("a".repeat(limit)).is_ok());
        assert!(matches!(
            OrderSim::new("a".repeat(limit + 1)),
            Err(Error::Validation {
                field: "address_id",
                ..
            })
        ));

        assert!(Localprefix::new(true, "0".repeat(limit)).is_ok());
        assert!(matches!(
            Localprefix::new(true, "0".repeat(limit + 1)),
            Err(Error::Validation { field: "value", .. })
        ));
    }

    #[test]
    fn documented_enums_carry_unknown_values_verbatim() {
        assert_eq!(
            DeviceFilter::from_wire("future"),
            DeviceFilter::Other("future".into())
        );
        assert_eq!(
            IncomingCallDisplay::from_wire("future"),
            IncomingCallDisplay::Other("future".into())
        );
        assert_eq!(SimState::from_wire("ACTIVE"), SimState::Active);
        // camelCase wire values for the type filter are folded case-insensitively.
        assert_eq!(DeviceFilter::from_wire("REGISTER"), DeviceFilter::Register);
    }

    #[test]
    fn response_models_decode_camel_case_and_snake_case_aliases() {
        let mobile: MobileDevice = serde_json::from_value(serde_json::json!({
            "id": "m0",
            "sim_state": "PENDING",
            "credentials": {"sim_id": "9"},
            "active_groups": [{"id": "g0", "alias": "Sales"}]
        }))
        .expect("mobile");
        assert_eq!(mobile.sim_state, Some(SimState::Pending));
        assert_eq!(
            mobile.credentials.as_ref().map(|c| c.sim_id.as_str()),
            Some("9")
        );
        assert_eq!(mobile.active_groups[0].alias, "Sales");

        let registered: RegisterDevice = serde_json::from_value(serde_json::json!({
            "address_url": "/addresses/1",
            "emergency_address_id": "1",
            "registered": [{"user_agent": "ua"}],
            "credentials": {"sip_server": "sip.example"}
        }))
        .expect("registered");
        assert_eq!(registered.address_url, "/addresses/1");
        assert_eq!(registered.emergency_address_id, "1");
        assert_eq!(registered.registered[0].user_agent, "ua");
        assert_eq!(registered.credentials.unwrap().sip_server, "sip.example");

        let external: ExternalDevice = serde_json::from_value(serde_json::json!({
            "incoming_call_display_state": "CALLED_NUMBER"
        }))
        .expect("external");
        assert_eq!(
            external.incoming_call_display,
            Some(IncomingCallDisplay::CalledNumber)
        );

        let unknown: RegisterDevice = serde_json::from_value(serde_json::json!({
            "type": "futureKind",
            "credentials": {"futureField": 1},
            "registered": [{"futureField": 2}]
        }))
        .expect("permissive");
        assert_eq!(unknown.kind, Some(DeviceKind::Other("futureKind".into())));
    }

    #[test]
    fn device_password_and_contingents_decode_permissively() {
        let password: DevicePassword =
            serde_json::from_value(serde_json::json!({"password": "x", "future": 1}))
                .expect("password");
        assert_eq!(password.password, "x");

        let contingents: DeviceContingents = serde_json::from_value(serde_json::json!({
            "contingents": [{"left": 1, "future": 2}]
        }))
        .expect("contingents");
        assert_eq!(contingents.contingents[0].left, 1);
        assert_eq!(Contingent::default().amount, 0);

        let mobile_creds: MobileCredentials =
            serde_json::from_value(serde_json::json!({"simId": "7"})).expect("creds");
        assert_eq!(mobile_creds.sim_id, "7");

        let register_creds: RegisterCredentials =
            serde_json::from_value(serde_json::json!({"sipServer": "s"})).expect("creds");
        assert_eq!(register_creds.sip_server, "s");

        let endpoint: RegisteredEndpoint =
            serde_json::from_value(serde_json::json!({"ip": "x"})).expect("endpoint");
        assert_eq!(endpoint.ip, "x");
    }

    #[test]
    fn phone_and_digit_builders_reject_unusable_values() {
        assert!(DeviceCallerId::new("4915112345678").is_ok());
        assert!(DeviceCallerId::new("+4915112345678").is_ok());
        assert!(DeviceCallerId::new("49 151 123").is_err());
        assert!(DeviceCallerId::new("491511").is_err());

        assert!(ExternalTargetNumber::new("4915112345678").is_ok());
        assert!(ExternalTargetNumber::new("00151").is_err());
        assert!(CreateExternalDevice::new("4915112345678").is_ok());
        assert!(CreateExternalDevice::new("4915").is_err());

        assert!(Localprefix::new(true, "030").is_ok());
        assert!(Localprefix::new(true, "03A0").is_err());
        assert!(Localprefix::new(true, "").is_err());

        assert!(CreateDevice::new(DeviceKind::Other("x".into())).is_err());

        let empty_mobile = CreateMobileDevice::new().to_json();
        assert_eq!(empty_mobile, serde_json::json!({}));
        let empty_register = CreateRegisterDevice::new().to_json();
        assert_eq!(empty_register, serde_json::json!({}));
    }
}

#[tokio::test]
async fn phoneline_account_crud_uses_the_documented_paths_and_types() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "p0",
            "alias": "Front desk",
            "devicesUrl": "https://api.sipgate.com/v2/w0/phonelines/p0/devices",
            "futureField": true
        }]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "id": "p1",
        "alias": "New line",
        "futureField": true
    })));
    transport.push_response(json_response(&serde_json::json!({
        "id": "p0",
        "alias": "Front desk",
        "voicemails": [{"id": "v0", "active": true, "timeout": 20}],
        "futureField": true
    })));
    transport.push_response(no_content());
    transport.push_response(no_content());

    let lines = client
        .user_phonelines("w0")
        .await
        .expect("listed user lines");
    assert_eq!(lines[0].id, "p0");
    assert!(lines[0].devices_url.ends_with("/devices"));

    let created = client.create_user_phoneline("w0").await.expect("created");
    assert_eq!(created.id, "p1");

    let line = client.user_phoneline("w0", "p0").await.expect("line");
    assert_eq!(line.voicemails[0].timeout, 20);

    client
        .set_user_phoneline_alias(
            "w0",
            "p0",
            &PhonelineAlias::new("Front desk").expect("alias"),
        )
        .await
        .expect("alias updated");
    client
        .delete_user_phoneline("w0", "p0")
        .await
        .expect("deleted");

    let calls = transport.calls();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[0].method.as_str(), "GET");
    assert_eq!(calls[0].url, "https://api.sipgate.com/v2/w0/phonelines");
    assert_eq!(calls[1].method.as_str(), "POST");
    assert_eq!(calls[1].url, "https://api.sipgate.com/v2/w0/phonelines");
    assert_eq!(calls[2].url, "https://api.sipgate.com/v2/w0/phonelines/p0");
    assert_eq!(calls[3].method.as_str(), "PUT");
    assert_eq!(calls[3].url, "https://api.sipgate.com/v2/w0/phonelines/p0");
    assert_eq!(json_body(&calls[3].body)["alias"], "Front desk");
    assert_eq!(calls[4].method.as_str(), "DELETE");
    assert_eq!(calls[4].url, "https://api.sipgate.com/v2/w0/phonelines/p0");
}

#[tokio::test]
async fn phoneline_settings_and_routing_reads_decode_typed_models() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "enabled": true,
        "target": "VOICEMAIL",
        "futureField": true
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{"id": "e0", "alias": "Desk phone", "type": "REGISTER"}]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{"active": true, "alias": "Mobile", "destination": "+4915112345678", "timeout": 20}]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{"id": "n0", "number": "+4915112345678", "localized": "01579-9912345", "type": "MOBILE"}]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{"id": "x0", "active": true, "alias": "Mobile", "destination": "+4915112345678"}]
    })));

    let setting = client
        .phoneline_block_anonymous_setting("w0", "p0")
        .await
        .expect("block anonymous");
    assert_eq!(setting.target, Some(BlockAnonymousTarget::Voicemail));

    let devices = client.phoneline_devices("w0", "p0").await.expect("devices");
    assert_eq!(devices[0].id, "e0");

    let forwardings = client
        .phoneline_forwardings("w0", "p0")
        .await
        .expect("forwardings");
    assert_eq!(forwardings[0].timeout, 20);

    let numbers = client.phoneline_numbers("w0", "p0").await.expect("numbers");
    assert_eq!(numbers[0].kind, Some(PhonelineNumberKind::Mobile));

    let parallel = client
        .phoneline_parallel_forwardings("w0", "p0")
        .await
        .expect("parallel");
    assert_eq!(parallel[0].id, "x0");

    let calls = transport.calls();
    assert_eq!(calls.len(), 5);
    assert_eq!(
        calls[0].url,
        "https://api.sipgate.com/v2/w0/phonelines/p0/blockanonymous"
    );
}

#[tokio::test]
async fn phoneline_sipgate_io_and_voicemail_reads_decode_typed_models() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "incomingActive": true,
        "incomingUrl": "https://example.com/in",
        "outgoingActive": false,
        "outgoingUrl": "https://example.com/out",
        "allowSelfSigned": false,
        "certificate": "-----BEGIN CERTIFICATE-----",
        "log": true,
        "futureField": true
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "created": "2015-10-21T19:28:00Z",
            "pushApiVersion": 2,
            "request": "event=newCall",
            "response": "HTTP/1.1 200 OK",
            "status": "200",
            "url": "https://demo.sipgate.io",
            "xmlError": ""
        }]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "v0",
            "alias": "Voicemail",
            "active": true,
            "timeout": 20,
            "accessNumber": "50000",
            "activeGreetingId": "g0",
            "activeGreetingAlias": "Default",
            "canTranscribe": true,
            "transcription": false
        }]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "g0",
            "alias": "Default greeting",
            "active": true,
            "greetingUrl": "https://example.com/greeting.mp3",
            "recordingEnabled": false
        }]
    })));

    let io = client
        .phoneline_sipgate_io("w0", "p0")
        .await
        .expect("sipgateio");
    assert!(io.incoming_active);
    assert!(io.log);

    let logs = client
        .phoneline_sipgate_io_logs("w0", "p0")
        .await
        .expect("logs");
    assert_eq!(logs[0].push_api_version, 2);

    let voicemails = client
        .phoneline_voicemails("w0", "p0")
        .await
        .expect("voicemails");
    assert_eq!(voicemails[0].active_greeting_id, "g0");

    let greetings = client
        .phoneline_voicemail_greetings("w0", "p0", "v0")
        .await
        .expect("greetings");
    assert_eq!(greetings[0].id, "g0");

    let calls = transport.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[0].url,
        "https://api.sipgate.com/v2/w0/phonelines/p0/sipgateio"
    );
    assert_eq!(
        calls[3].url,
        "https://api.sipgate.com/v2/w0/phonelines/p0/voicemails/v0/greetings"
    );
}

#[tokio::test]
async fn phoneline_settings_and_routing_writes_use_documented_bodies() {
    let (transport, _, client) = harness();
    for _ in 0..3 {
        transport.push_response(no_content());
    }
    transport.push_response(json_response(&serde_json::json!({
        "active": true,
        "alias": "Mobile",
        "destination": "+4915112345678",
        "timeout": 20
    })));
    for _ in 0..3 {
        transport.push_response(no_content());
    }

    let blocking = PhonelineBlockAnonymousSetting::reject(true);
    client
        .set_phoneline_block_anonymous_setting("w0", "p0", &blocking)
        .await
        .expect("blocking");
    client
        .add_device_to_phoneline("w0", "p0", &RouteDeviceRequest::new("e0").expect("device"))
        .await
        .expect("device added");
    client
        .remove_device_from_phoneline("w0", "p0", "e0")
        .await
        .expect("device removed");
    let rules = PhonelineForwardings::new(vec![PhonelineForwardingRule::new(
        true,
        "+4915112345678",
        20,
    )
    .expect("rule")])
    .expect("rules");
    let updated = client
        .set_phoneline_forwardings("w0", "p0", &rules)
        .await
        .expect("forwarding updated");
    assert!(updated.active);
    let parallel = ParallelForwardingRequest::new("+4915112345678")
        .expect("parallel")
        .with_alias("Mobile");
    client
        .add_phoneline_parallel_forwarding("w0", "p0", &parallel)
        .await
        .expect("parallel added");
    client
        .update_phoneline_parallel_forwarding("w0", "p0", "x0", &parallel)
        .await
        .expect("parallel updated");
    client
        .delete_phoneline_parallel_forwarding("w0", "p0", "x0")
        .await
        .expect("parallel deleted");

    let calls = transport.calls();
    assert_eq!(calls.len(), 7);
    assert_eq!(json_body(&calls[0].body)["target"], "REJECT");
    assert_eq!(json_body(&calls[1].body)["deviceId"], "e0");
    assert_eq!(json_body(&calls[3].body)["forwardings"][0]["timeout"], 20);
    assert_eq!(json_body(&calls[4].body)["destination"], "+4915112345678");
}

#[tokio::test]
async fn phoneline_sipgate_io_and_voicemail_writes_use_documented_bodies() {
    let (transport, _, client) = harness();
    for _ in 0..6 {
        transport.push_response(no_content());
    }

    let io = PhonelineSipgateIo::new("https://example.com/in", "https://example.com/out")
        .expect("io")
        .with_incoming_active(true)
        .with_outgoing_active(true)
        .with_allow_self_signed(true)
        .with_certificate("-----BEGIN CERTIFICATE-----")
        .with_log(true);
    client
        .set_phoneline_sipgate_io("w0", "p0", &io)
        .await
        .expect("io updated");
    client
        .update_phoneline_voicemail(
            "w0",
            "p0",
            "v0",
            &VoicemailSettingsUpdate::new(true, false).with_timeout(0),
        )
        .await
        .expect("voicemail updated");
    let greeting =
        VoicemailGreetingRequest::new("greeting.mp3", "RG8uIE9yIGRvIG5vdC4=").expect("greeting");
    client
        .add_phoneline_voicemail_greeting("w0", "p0", "v0", &greeting)
        .await
        .expect("greeting added");
    client
        .update_phoneline_voicemail_greeting(
            "w0",
            "p0",
            "v0",
            "g0",
            &VoicemailGreetingUpdate::new(true),
        )
        .await
        .expect("greeting updated");
    client
        .delete_phoneline_voicemail_greeting("w0", "p0", "v0", "g0")
        .await
        .expect("greeting deleted");
    client
        .update_phoneline_voicemail_transcription(
            "w0",
            "p0",
            "v0",
            &VoicemailTranscriptionUpdate::new(true),
        )
        .await
        .expect("transcription updated");

    let calls = transport.calls();
    assert_eq!(calls.len(), 6);
    assert_eq!(json_body(&calls[0].body)["incomingActive"], true);
    assert_eq!(json_body(&calls[1].body)["timeout"], 0);
    assert_eq!(
        json_body(&calls[2].body)["base64Content"],
        "RG8uIE9yIGRvIG5vdC4="
    );
    assert_eq!(json_body(&calls[3].body)["active"], true);
    assert_eq!(
        calls[5].url,
        "https://api.sipgate.com/v2/w0/phonelines/p0/voicemails/v0/transcriptions"
    );
}

#[tokio::test]
async fn phoneline_path_parameters_and_bytes_are_validated_before_the_wire() {
    let (transport, _, client) = harness();
    for bad in ["", ".", "..", "a/b", "a?b", "a b", "a\tb"] {
        assert!(matches!(
            client.user_phonelines(bad).await,
            Err(Error::Validation {
                field: "user_id",
                ..
            })
        ));
        assert!(matches!(
            client.user_phoneline("w0", bad).await,
            Err(Error::Validation {
                field: "phoneline_id",
                ..
            })
        ));
    }
    assert!(matches!(
        client.remove_device_from_phoneline("w0", "p0", "a/b").await,
        Err(Error::Validation {
            field: "device_id",
            ..
        })
    ));
    assert!(matches!(
        client
            .delete_phoneline_voicemail_greeting("w0", "p0", "v0", "a/b")
            .await,
        Err(Error::Validation {
            field: "greeting_id",
            ..
        })
    ));
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn phoneline_request_boundaries_are_proven() {
    let limit = 1024 * 1024;
    assert!(PhonelineAlias::new("a".repeat(limit)).is_ok());
    assert!(PhonelineAlias::new("a".repeat(limit + 1)).is_err());

    assert!(RouteDeviceRequest::new("e0").is_ok());
    assert!(RouteDeviceRequest::new("a/b").is_err());

    assert!(PhonelineForwardingRule::new(true, "+4915112345", 20).is_ok());
    assert!(PhonelineForwardingRule::new(true, "123", 20).is_err());

    assert!(PhonelineSipgateIo::new("https://example.com/in", "https://example.com/out").is_ok());
    assert!(PhonelineSipgateIo::new("example.com/in", "https://example.com/out").is_err());

    assert!(VoicemailGreetingRequest::new("g.mp3", "A".repeat(15_000_000)).is_ok());
    assert!(VoicemailGreetingRequest::new("g.mp3", "A".repeat(15_000_001)).is_err());
    assert!(VoicemailGreetingRequest::new("g.mp3", "not base64").is_err());
}

#[tokio::test]
async fn phoneline_models_are_permissive_and_carry_unknown_variants() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({
        "items": [{
            "id": "n0",
            "number": "+4915112345678",
            "localized": "01579-9912345",
            "type": "SATELLITE",
            "futureField": true
        }]
    })));
    transport.push_response(json_response(&serde_json::json!({
        "incoming_active": true,
        "incoming_url": "https://example.com/in",
        "outgoing_active": false,
        "outgoing_url": "https://example.com/out",
        "allow_self_signed": false,
        "certificate": "",
        "log": false,
        "futureField": true
    })));

    let numbers = client.phoneline_numbers("w0", "p0").await.expect("numbers");
    assert_eq!(
        numbers[0].kind,
        Some(PhonelineNumberKind::Other("SATELLITE".into()))
    );

    let io = client.phoneline_sipgate_io("w0", "p0").await.expect("io");
    assert!(io.incoming_active);
    assert_eq!(io.incoming_url, "https://example.com/in");
}

#[tokio::test]
async fn phoneline_response_shape_mismatch_is_a_typed_json_error() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"id": 1})));

    let error = client
        .user_phoneline("w0", "p0")
        .await
        .expect_err("wrong shape");
    assert!(matches!(error, Error::Json { .. }));
}

// --- BEGIN REST v2 contacts resource tests (#165) ---

mod contacts {
    use super::*;
    use sipgate_flow::rest::{
        ContactAddressRequest, ContactCsvImport, ContactCsvQuery, ContactDeleteRequest,
        ContactDeleteResult, ContactEmailRequest, ContactGoogleImport, ContactImportResult,
        ContactNumberRequest, ContactPage, ContactQuery, ContactRequest, ContactRequestScope,
        ContactScopeQuery, ContactUpsertResult, ContactVCardsQuery, ContactVCardsRequest,
        ContactWebsiteRequest, InternalContact, StructuredVCard, StructuredVCardItem,
        StructuredVCardMeta, StructuredVCardUpsertData, MAX_CONTACT_PAGE_LIMIT,
    };

    #[tokio::test]
    async fn contacts_list_sends_no_query_by_default() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "items": [{"id": "c1", "name": "Ada"}],
            "totalCount": 1
        })));
        let page = client
            .contact_page(&ContactQuery::new())
            .await
            .expect("page");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.total_count, Some(1));
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "GET");
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts");
        assert_eq!(call.body, Body::Empty);
    }

    #[tokio::test]
    async fn contacts_list_renders_every_documented_paging_parameter() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"items": []})));
        let query = ContactQuery::new()
            .with_limit(100)
            .expect("limit")
            .with_offset(20)
            .expect("offset")
            .with_last_id("c9")
            .expect("last id")
            .with_scopes([ContactScopeQuery::Private, ContactScopeQuery::Shared])
            .with_phonenumbers(["+4915112345678"])
            .expect("number");
        client.contact_page(&query).await.expect("page");
        let call = transport.only_call();
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts?phonenumbers=%2B4915112345678&limit=100&offset=20&lastId=c9&scopes=PRIVATE&scopes=SHARED");
    }

    #[test]
    fn contacts_page_limit_boundaries() {
        assert!(ContactQuery::new().with_limit(1).is_ok());
        assert!(ContactQuery::new()
            .with_limit(MAX_CONTACT_PAGE_LIMIT)
            .is_ok());
        assert!(ContactQuery::new().with_limit(0).is_err());
        assert!(ContactQuery::new()
            .with_limit(MAX_CONTACT_PAGE_LIMIT + 1)
            .is_err());
        assert_eq!(MAX_CONTACT_PAGE_LIMIT, 5000);
    }

    #[test]
    fn contacts_offset_boundaries() {
        assert!(ContactQuery::new().with_offset(0).is_ok());
        assert!(ContactQuery::new().with_offset(i64::from(i32::MAX)).is_ok());
        assert!(ContactQuery::new().with_offset(-1).is_err());
        assert!(ContactQuery::new()
            .with_offset(i64::from(i32::MAX) + 1)
            .is_err());
    }

    #[test]
    fn contacts_last_id_is_validated_before_the_wire() {
        assert!(ContactQuery::new().with_last_id("c1").is_ok());
        assert!(ContactQuery::new().with_last_id("").is_err());
        assert!(ContactQuery::new().with_last_id("a/b").is_err());
    }

    #[test]
    fn contacts_scope_query_round_trips_and_keeps_unknowns() {
        assert_eq!(
            ContactScopeQuery::from_wire("private"),
            ContactScopeQuery::Private
        );
        assert_eq!(
            ContactScopeQuery::from_wire("Shared"),
            ContactScopeQuery::Shared
        );
        assert_eq!(
            ContactScopeQuery::from_wire("INTERNAL"),
            ContactScopeQuery::Internal
        );
        assert_eq!(
            ContactScopeQuery::from_wire("FUTURE"),
            ContactScopeQuery::Other("FUTURE".into())
        );
    }

    #[test]
    fn contact_request_scope_models_the_combined_value() {
        assert_eq!(ContactRequestScope::Private.as_str(), "PRIVATE");
        assert_eq!(
            ContactRequestScope::from_wire("private,shared"),
            ContactRequestScope::PrivateShared
        );
        assert_eq!(
            ContactRequestScope::PrivateShared.as_str(),
            "PRIVATE,SHARED"
        );
        assert_eq!(
            ContactRequestScope::from_wire("future"),
            ContactRequestScope::Other("future".into())
        );
    }

    #[tokio::test]
    async fn create_contact_posts_the_body_and_accepts_a_201() {
        let (transport, _, client) = harness();
        transport.push_response(response(201, &[("Content-Type", "application/json")], b""));
        let request = ContactRequest::new()
            .with_name("Ada Lovelace")
            .expect("name")
            .with_given("Ada")
            .expect("given")
            .with_family("Lovelace")
            .expect("family")
            .with_scope(ContactRequestScope::Shared)
            .with_emails([ContactEmailRequest::new("ada@example.com").expect("email")])
            .with_numbers([ContactNumberRequest::new("+4915112345678").expect("number")])
            .with_websites([ContactWebsiteRequest::new("example.com").expect("website")])
            .with_addresses([ContactAddressRequest::new()
                .with_street_address("1 A St")
                .expect("street")]);
        client.create_contact(&request).await.expect("created");
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "POST");
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts");
        let body = json_body(&call.body);
        assert_eq!(body["name"], "Ada Lovelace");
        assert_eq!(body["scope"], "SHARED");
        assert_eq!(body["emails"][0]["email"], "ada@example.com");
        assert_eq!(body["numbers"][0]["number"], "+4915112345678");
        assert_eq!(body["addresses"][0]["streetAddress"], "1 A St");
    }

    #[tokio::test]
    async fn update_contact_puts_the_body_and_accepts_a_204() {
        let (transport, _, client) = harness();
        transport.push_response(no_content());
        let request = ContactRequest::new().with_name("Ada").expect("name");
        client
            .update_contact("c1", &request)
            .await
            .expect("updated");
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "PUT");
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts/c1");
        assert_eq!(json_body(&call.body)["name"], "Ada");
    }

    #[tokio::test]
    async fn delete_one_contact_reads_the_delete_count() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"deleteCount": 1})));
        let result: ContactDeleteResult = client.delete_contact("c1").await.expect("deleted");
        assert_eq!(result.delete_count, 1);
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "DELETE");
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts/c1");
    }

    #[tokio::test]
    async fn bulk_delete_posts_ids_and_scopes() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"deleteCount": 2})));
        let request = ContactDeleteRequest::new()
            .with_contact_ids(["c1", "c2"])
            .expect("ids")
            .with_scopes([ContactScopeQuery::Shared])
            .with_source("api");
        let result = client.delete_contacts(&request).await.expect("deleted");
        assert_eq!(result.delete_count, 2);
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "DELETE");
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts");
        let body = json_body(&call.body);
        assert_eq!(body["contactIds"], serde_json::json!(["c1", "c2"]));
        assert_eq!(body["scope"], serde_json::json!(["SHARED"]));
        assert_eq!(body["source"], "api");
    }

    #[tokio::test]
    async fn csv_export_returns_text() {
        let (transport, _, client) = harness();
        transport.push_response(response(
            200,
            &[("Content-Type", "text/csv")],
            b"firstname,lastname\nAda,Lovelace\n",
        ));
        let query = ContactCsvQuery::new([ContactScopeQuery::Private]);
        let csv = client.export_contacts_csv(&query).await.expect("csv");
        assert!(csv.starts_with("firstname,lastname"));
        let call = transport.only_call();
        assert_eq!(
            call.url,
            "https://api.sipgate.com/v2/contacts/csv?scope=PRIVATE"
        );
    }

    #[tokio::test]
    async fn csv_import_posts_base64_content() {
        let (transport, _, client) = harness();
        transport.push_response(no_content());
        let import = ContactCsvImport::new("Zmlyc3Q=").expect("import");
        client.import_contacts_csv(&import).await.expect("imported");
        let call = transport.only_call();
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts/import/csv");
        assert_eq!(json_body(&call.body)["base64Content"], "Zmlyc3Q=");
    }

    #[tokio::test]
    async fn google_import_posts_the_token_and_reads_total_count() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({"totalCount": 4})));
        let import = ContactGoogleImport::new("oauth")
            .expect("token")
            .with_scope(ContactRequestScope::Private);
        let result: ContactImportResult = client
            .import_contacts_google(&import)
            .await
            .expect("imported");
        assert_eq!(result.total_count, 4);
        let call = transport.only_call();
        assert_eq!(
            call.url,
            "https://api.sipgate.com/v2/contacts/import/google"
        );
        let body = json_body(&call.body);
        assert_eq!(body["token"], "oauth");
        assert_eq!(body["scope"], "PRIVATE");
    }

    #[tokio::test]
    async fn internal_contacts_are_typed_reads() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "items": [{
                "contactId": "internal-1",
                "id": "0a50",
                "name": "Ada Lovelace",
                "mobile": ["+4915112345678"],
                "futureField": true
            }]
        })));
        let contacts: Vec<InternalContact> = client.internal_contacts().await.expect("internal");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, "Ada Lovelace");
        let call = transport.only_call();
        assert_eq!(call.url, "https://api.sipgate.com/v2/contacts/internal");
    }

    #[tokio::test]
    async fn vcard_get_renders_the_query_and_parses_the_page() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "contacts": [{"meta": {"UUID": "u1"}, "items": {"FN": [{"value": "Ada"}]}}],
            "overallMatches": 1
        })));
        let query = ContactVCardsQuery::new([ContactScopeQuery::Shared])
            .with_limit(50)
            .expect("limit")
            .with_labels(["friend"])
            .expect("labels")
            .with_contact_ids(["c1"])
            .expect("ids")
            .with_wanted_fields(["name"])
            .expect("fields")
            .with_filter("Ada")
            .expect("filter");
        let page = client.contact_vcards(&query).await.expect("vcards");
        assert_eq!(page.contacts.len(), 1);
        assert_eq!(page.overall_matches, Some(1));
        let call = transport.only_call();
        assert!(call
            .url
            .starts_with("https://api.sipgate.com/v2/contacts/vcard?"));
        assert!(call.url.contains("scope=SHARED"));
        assert!(call.url.contains("limit=50"));
        assert!(call.url.contains("filter=Ada"));
    }

    #[tokio::test]
    async fn vcard_put_posts_entries_and_reads_results() {
        let (transport, _, client) = harness();
        transport.push_response(json_response(&serde_json::json!({
            "result": [{"contactId": "c1", "valid_from": "2020-01-01"}]
        })));
        let request = ContactVCardsRequest::new()
            .with_data([StructuredVCardUpsertData::new().with_contact_id("c1")]);
        let result = client
            .put_contact_vcards(ContactScopeQuery::Private, &request)
            .await
            .expect("stored");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].contact_id, "c1");
        assert_eq!(result[0].valid_from, "2020-01-01");
        let call = transport.only_call();
        assert_eq!(call.method.as_str(), "PUT");
        assert_eq!(
            call.url,
            "https://api.sipgate.com/v2/contacts/vcard?scope=PRIVATE"
        );
        assert_eq!(json_body(&call.body)["data"][0]["contactId"], "c1");
    }

    #[test]
    fn contacts_models_decode_camel_and_snake_case_and_keep_unknowns() {
        let page: ContactPage = serde_json::from_value(serde_json::json!({
            "items": [{
                "id": "c1",
                "name": "Ada",
                "scope": "PRIVATE",
                "addresses": [{"address_id": "a1", "address1": "1 A St", "numbers_url": "/u"}],
                "emails": [{"email": "a@b.c"}],
                "numbers": [{"id": "n1", "number": "+49", "type": "MOBILE"}],
                "websites": [{"url": "example.com"}],
                "organization": [["Acme", "Eng"]],
                "futureField": true
            }],
            "total_count": 1
        }))
        .expect("page");
        assert_eq!(page.total_count, Some(1));
        assert_eq!(page.items[0].addresses[0].address_id, "a1");
        assert_eq!(
            page.items[0].numbers[0]
                .kind
                .as_ref()
                .map(sipgate_flow::rest::ContactNumberKind::as_str),
            Some("mobile")
        );

        let item: StructuredVCardItem = serde_json::from_value(serde_json::json!({
            "poBox": "1",
            "postCode": "40219",
            "xlocalNumber": "+49",
            "futureField": true
        }))
        .expect("item");
        assert_eq!(item.po_box, "1");
        assert_eq!(item.post_code, "40219");
        assert_eq!(item.x_local_number, "+49");

        let card: StructuredVCard = serde_json::from_value(serde_json::json!({
            "meta": {"uuid": "u1", "validFrom": "2020-01-01"},
            "items": {}
        }))
        .expect("card");
        assert_eq!(card.meta.uuid, "u1");
        assert_eq!(card.meta.valid_from, "2020-01-01");
    }

    #[test]
    fn contact_upsert_result_reads_valid_from() {
        let result: ContactUpsertResult = serde_json::from_value(serde_json::json!({
            "contactId": "c1",
            "valid_from": "2020-01-01"
        }))
        .expect("result");
        assert_eq!(result.contact_id, "c1");
        assert_eq!(result.valid_from, "2020-01-01");
    }

    #[test]
    fn structured_vcard_meta_defaults_when_absent() {
        let card: StructuredVCard = serde_json::from_value(serde_json::json!({})).expect("card");
        assert_eq!(card, StructuredVCard::default());
        assert_eq!(StructuredVCardMeta::default().uuid, "");
    }

    #[test]
    fn contact_id_fields_are_validated_before_the_wire() {
        assert!(ContactDeleteRequest::new().with_contact_ids(["c1"]).is_ok());
        assert!(ContactDeleteRequest::new().with_contact_ids([""]).is_err());
        assert!(ContactDeleteRequest::new()
            .with_contact_ids(["a/b"])
            .is_err());
    }

    #[tokio::test]
    async fn contact_ids_are_validated_before_the_wire() {
        let (transport, _, client) = harness();
        for bad in ["", ".", "..", "a/b", "a?b", "a b"] {
            let error = client.delete_contact(bad).await.expect_err(bad);
            assert!(
                matches!(
                    error,
                    Error::Validation {
                        field: "contact_id",
                        ..
                    }
                ),
                "{bad:?} produced {error:?}"
            );
        }
        assert_eq!(transport.call_count(), 0);
    }

    #[test]
    fn contact_csv_import_rejects_empty_and_non_base64() {
        assert!(ContactCsvImport::new("Zmlyc3Q=").is_ok());
        assert!(ContactCsvImport::new("").is_err());
        assert!(ContactCsvImport::new("not base64!").is_err());
    }

    #[test]
    fn contact_google_import_rejects_empty_token() {
        assert!(ContactGoogleImport::new("token").is_ok());
        assert!(ContactGoogleImport::new("").is_err());
    }

    #[test]
    fn contact_request_fields_reject_oversized_values() {
        let just_inside = "a".repeat(1024 * 1024);
        let just_outside = "a".repeat(1024 * 1024 + 1);
        assert!(ContactRequest::new().with_name(just_inside).is_ok());
        assert!(ContactRequest::new().with_name(just_outside).is_err());
        assert!(ContactRequest::new().with_name("").is_err());
    }

    #[test]
    fn contact_number_request_validates_e164() {
        assert!(ContactNumberRequest::new("+4915112345678").is_ok());
        assert!(ContactNumberRequest::new("123").is_err());
        assert!(ContactNumberRequest::new("+0123456789").is_err());
    }

    #[test]
    fn contact_email_request_rejects_empty() {
        assert!(ContactEmailRequest::new("a@b.c").is_ok());
        assert!(ContactEmailRequest::new("").is_err());
    }

    #[test]
    fn contacts_accessors_and_remaining_builders_are_exercised() {
        // Accessors.
        assert_eq!(
            ContactCsvImport::new("Zm9v").expect("import").content(),
            "Zm9v"
        );
        let import = ContactGoogleImport::new("t").expect("token");
        assert_eq!(import.to_json()["token"], "t");
        assert_eq!(
            ContactCsvQuery::new([ContactScopeQuery::Private])
                .scopes()
                .len(),
            1
        );
        assert_eq!(ContactVCardsRequest::new().data(), []);
        assert_eq!(ContactScopeQuery::Internal.as_str(), "INTERNAL");
        assert_eq!(ContactRequestScope::Internal.as_str(), "INTERNAL");
        assert_eq!(ContactRequestScope::Other("x".into()).as_str(), "x");

        // ContactRequest optional setters.
        assert_eq!(ContactRequest::new().with_id("c1").to_json()["id"], "c1");
        assert_eq!(
            ContactRequest::new()
                .with_note("hi")
                .expect("note")
                .to_json()["note"],
            "hi"
        );
        assert!(ContactRequest::new().with_picture("Zm9v").is_ok());
        assert!(ContactRequest::new().with_picture("nope!").is_err());

        // vCard query offset/lastId builders.
        let query = ContactVCardsQuery::new([ContactScopeQuery::Private])
            .with_offset(5)
            .expect("offset")
            .with_last_id("c1")
            .expect("last id");
        let path = query.path();
        assert!(path.contains("offset=5"), "{path}");
        assert!(path.contains("lastId=c1"), "{path}");

        // Address request optional setters.
        let address = ContactAddressRequest::new()
            .with_street_address("1 A St")
            .expect("street")
            .with_extended_address("Flat A")
            .expect("extended")
            .with_city("Berlin")
            .expect("city")
            .with_po_box("1")
            .expect("po box")
            .with_postal_code("10115")
            .expect("postal")
            .with_region("BE")
            .expect("region")
            .with_country("DE")
            .expect("country")
            .with_types(["home"]);
        let body = address.to_json();
        assert_eq!(body["country"], "DE");
        assert_eq!(body["extendedAddress"], "Flat A");

        // Organization rows.
        let request =
            ContactRequest::new().with_organization([["Acme".to_string(), "Eng".to_string()]]);
        assert_eq!(request.to_json()["organization"][0][1], "Eng");
    }

    #[test]
    fn contact_vcard_limit_boundaries_match_the_list_limit() {
        let query = ContactVCardsQuery::new([ContactScopeQuery::Private]);
        assert!(query.clone().with_limit(MAX_CONTACT_PAGE_LIMIT).is_ok());
        assert!(query.clone().with_limit(0).is_err());
        assert!(query.with_limit(MAX_CONTACT_PAGE_LIMIT + 1).is_err());
    }
}
