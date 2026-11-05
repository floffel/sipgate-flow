//! The `flow` facade is a promise, checked at compile time.
//!
//! Every submodule under `flow` stays `pub`, so its items are reachable as
//! `flow::action::…`, `flow::event::…` and so on. The `pub use` block in
//! `flow/mod.rs` adds a curated second path that callers actually reach for,
//! and nothing but a test keeps it in sync: a type added to a submodule and
//! forgotten in the facade would compile and ship unnoticed. The checks below
//! force that drift to fail the build instead.

#![allow(clippy::type_complexity)]

// Every re-exported name must resolve both through its submodule path and
// through the facade. `const _: fn(A) = |x| { let _: B = x; };` type-checks the
// two paths as the same type at compile time, so a facade that drops a name -
// or a submodule that reshapes a type the facade still promises - cannot
// compile.

// --- `flow::action` -------------------------------------------------------

const _: fn(sipgate_flow::flow::action::Action) = |v| {
    let _: sipgate_flow::flow::Action = v;
};
const _: fn(sipgate_flow::flow::action::ActionKind) = |v| {
    let _: sipgate_flow::flow::ActionKind = v;
};
const _: fn(sipgate_flow::flow::action::Audio) = |v| {
    let _: sipgate_flow::flow::Audio = v;
};
const _: fn(sipgate_flow::flow::action::BargeInConfig) = |v| {
    let _: sipgate_flow::flow::BargeInConfig = v;
};
const _: fn(sipgate_flow::flow::action::BargeInStrategy) = |v| {
    let _: sipgate_flow::flow::BargeInStrategy = v;
};
const _: fn(sipgate_flow::flow::action::ConfigureTranscription) = |v| {
    let _: sipgate_flow::flow::ConfigureTranscription = v;
};
const _: fn(sipgate_flow::flow::action::MixAudio) = |v| {
    let _: sipgate_flow::flow::MixAudio = v;
};
const _: fn(sipgate_flow::flow::action::SendSms) = |v| {
    let _: sipgate_flow::flow::SendSms = v;
};
const _: fn(sipgate_flow::flow::action::Speak) = |v| {
    let _: sipgate_flow::flow::Speak = v;
};
const _: fn(sipgate_flow::flow::action::TranscriptionProvider) = |v| {
    let _: sipgate_flow::flow::TranscriptionProvider = v;
};
const _: fn(sipgate_flow::flow::action::Transfer) = |v| {
    let _: sipgate_flow::flow::Transfer = v;
};
const _: fn(sipgate_flow::flow::action::Tts) = |v| {
    let _: sipgate_flow::flow::Tts = v;
};
const _: fn(sipgate_flow::flow::action::Vad) = |v| {
    let _: sipgate_flow::flow::Vad = v;
};

// --- `flow::client` -------------------------------------------------------

const _: fn(sipgate_flow::flow::client::OutboundCall) = |v| {
    let _: sipgate_flow::flow::OutboundCall = v;
};
const _: fn(sipgate_flow::flow::client::OutboundCallReceipt) = |v| {
    let _: sipgate_flow::flow::OutboundCallReceipt = v;
};
// `FlowClient` is generic over its transport; a bound-checked helper proves the
// facade path is the same type without naming a concrete transport.
#[allow(dead_code)]
fn flow_client_is_reachable_over_the_facade<T: sipgate_flow::Transport>(
    client: sipgate_flow::flow::FlowClient<T>,
) -> sipgate_flow::flow::client::FlowClient<T> {
    client
}
const _: &str = sipgate_flow::flow::DEFAULT_BASE_URL;
const _: &str = sipgate_flow::flow::client::DEFAULT_BASE_URL;

// --- `flow::event` --------------------------------------------------------

const _: fn(sipgate_flow::flow::event::Direction) = |v| {
    let _: sipgate_flow::flow::Direction = v;
};
const _: fn(sipgate_flow::flow::event::ErrorCode) = |v| {
    let _: sipgate_flow::flow::ErrorCode = v;
};
const _: fn(sipgate_flow::flow::event::Event) = |v| {
    let _: sipgate_flow::flow::Event = v;
};
const _: fn(sipgate_flow::flow::event::EventPayload) = |v| {
    let _: sipgate_flow::flow::EventPayload = v;
};
const _: fn(sipgate_flow::flow::event::Session) = |v| {
    let _: sipgate_flow::flow::Session = v;
};
const _: fn(sipgate_flow::flow::event::Severity) = |v| {
    let _: sipgate_flow::flow::Severity = v;
};
const _: fn(sipgate_flow::flow::event::SmsFailureReason) = |v| {
    let _: sipgate_flow::flow::SmsFailureReason = v;
};
const _: fn(sipgate_flow::flow::event::TransferFailedReason) = |v| {
    let _: sipgate_flow::flow::TransferFailedReason = v;
};
const _: usize = sipgate_flow::flow::MAX_EVENT_BODY_BYTES;
const _: usize = sipgate_flow::flow::event::MAX_EVENT_BODY_BYTES;

// --- `flow::response` -----------------------------------------------------

const _: fn(sipgate_flow::flow::response::FlowResponse) = |v| {
    let _: sipgate_flow::flow::FlowResponse = v;
};

// --- `flow::webhook` ------------------------------------------------------

const _: fn(sipgate_flow::flow::webhook::WebhookVerifier) = |v| {
    let _: sipgate_flow::flow::WebhookVerifier = v;
};
const _: fn(&str) -> bool = sipgate_flow::flow::is_json_content_type;
const _: &str = sipgate_flow::flow::SECRET_HEADER;
const _: &str = sipgate_flow::flow::webhook::SECRET_HEADER;
const _: &str = sipgate_flow::flow::SECRET_HEADER_LEGACY;
const _: &str = sipgate_flow::flow::webhook::SECRET_HEADER_LEGACY;
const _: usize = sipgate_flow::flow::DEFAULT_MAX_BODY_BYTES;
const _: usize = sipgate_flow::flow::webhook::DEFAULT_MAX_BODY_BYTES;

// --- `flow::socket` (the `websocket` feature) -----------------------------

#[cfg(feature = "websocket")]
const _: fn(sipgate_flow::flow::socket::FlowSocket<sipgate_flow::flow::socket::MockConnection>) =
    |v| {
        let _: sipgate_flow::flow::FlowSocket<sipgate_flow::flow::socket::MockConnection> = v;
    };
#[cfg(feature = "websocket")]
const _: fn(sipgate_flow::flow::socket::Frame) = |v| {
    let _: sipgate_flow::flow::Frame = v;
};
#[cfg(feature = "websocket")]
const _: fn(sipgate_flow::flow::socket::AcceptBackoff) = |v| {
    let _: sipgate_flow::flow::AcceptBackoff = v;
};
#[cfg(feature = "websocket")]
const _: fn(sipgate_flow::flow::socket::MockConnection) = |v| {
    let _: sipgate_flow::flow::MockConnection = v;
};
// The trait is pinned the way a caller uses it: a bound written against the
// facade path must accept an impl written against `flow::socket::Connection`,
// which is what proves both paths name one trait.
#[cfg(feature = "websocket")]
const _: () = {
    fn requires<C: sipgate_flow::flow::Connection>(_connection: &C) {}
    #[allow(dead_code)]
    fn bridge(connection: &sipgate_flow::flow::socket::MockConnection) {
        requires(connection);
    }
};
#[cfg(feature = "websocket")]
const _: usize = sipgate_flow::flow::socket::MAX_SOCKET_MESSAGE_BYTES;

// --- the failure path a caller matches on --------------------------------

// The parse/verification/action errors are `sipgate_flow::Error`; the facade
// forwards the same type so `flow::Error` and `sipgate_flow::Error` are one
// type, not two lookalikes.
const _: fn(sipgate_flow::flow::Error) = |v| {
    let _: sipgate_flow::Error = v;
};
const _: fn(sipgate_flow::Error) = |v| {
    let _: sipgate_flow::flow::Error = v;
};
const _: fn(sipgate_flow::flow::Result<sipgate_flow::flow::Event>) = |v| {
    let _: sipgate_flow::Result<sipgate_flow::flow::Event> = v;
};

// `use` paths a downstream crate would actually write. If a name leaves the
// facade, one of these imports stops resolving.
#[allow(unused_imports)]
mod imports {
    use sipgate_flow::flow::{
        is_json_content_type, Action, ActionKind, Audio, BargeInConfig, BargeInStrategy,
        ConfigureTranscription, Direction, Error, ErrorCode, Event, EventPayload, FlowClient,
        FlowResponse, MixAudio, OutboundCall, OutboundCallReceipt, Result, SendSms, Session,
        Severity, SmsFailureReason, Speak, TranscriptionProvider, Transfer, TransferFailedReason,
        Tts, Vad, WebhookVerifier, DEFAULT_BASE_URL, DEFAULT_MAX_BODY_BYTES, MAX_EVENT_BODY_BYTES,
        SECRET_HEADER, SECRET_HEADER_LEGACY,
    };
    #[cfg(feature = "websocket")]
    use sipgate_flow::flow::{
        AcceptBackoff, Connection, FlowSocket, Frame, MockConnection, MAX_SOCKET_MESSAGE_BYTES,
    };
}
