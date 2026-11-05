# sipgate-flow

Typed, tolerant client for **sipgate flow**, the classic **sipgate.io Push API**
and the **sipgate REST API v2**.

sipgate ships three webhook-shaped protocols that are easy to mix up, and 0.1
mixed two of them up. This crate keeps them apart:

| Half | What it does | Docs |
| --- | --- | --- |
| `flow` | Your webhook **receives** events (`session_start`, `user_speak`, `dtmf_received`, …) and **returns** actions (`speak`, `audio`, `transfer`, …) in the response. There is no separate endpoint to post an action to. Flow can also open a **WebSocket** to you and exchange the same events and actions as JSON messages. | [flow.sipgate.io/api](https://flow.sipgate.io/api/) |
| `push` | The classic Push API: sipgate POSTs a form-encoded event (`newCall`, `answer`, `hangup`, `dtmf`) and your handler answers with an XML `<Response>` (`Dial`, `Play`, `Gather`, `Reject`, `Hangup`). | [en.sipgate.io/push-api](https://en.sipgate.io/push-api/api-references) |
| `rest` | The imperative API at `api.sipgate.com/v2`: SMS, fax, outbound calls, and live call control (hangup, DTMF, announcement, recording, hold, mute, transfer). | [api.sipgate.com/v2/doc](https://api.sipgate.com/v2/doc) |

Every shape was checked against public documentation and is cited in
**[`docs/contracts.md`](docs/contracts.md)** — including the ones that could not
be verified, which are listed there and are never assumed correct in code.

## Answering a webhook

```rust
use sipgate_flow::{Action, EventPayload, FlowResponse, WebhookVerifier};

let verifier = WebhookVerifier::new(std::env::var("AI_FLOW_SHARED_SECRET")?)?;

// `secret` and `content_type` come from the request headers; `body` is the raw
// bytes. This returns 401 for a wrong secret and 415 for a form-encoded
// (Push API) request, before anything is parsed.
let event = verifier.verify_and_parse(secret, content_type, body)?;

// No session id means the event cannot be addressed: answer `204` instead of
// inventing a default the service would reject.
let Some(session) = event.session_id() else {
    return Ok(FlowResponse::none());
};

let response = match event.payload() {
    EventPayload::SessionStart { transfer_failed_reason: Some(reason), .. } => {
        let text = if reason.is_worth_retrying() {
            "Die Leitung ist besetzt. Soll ich es bei einer Kollegin versuchen?"
        } else {
            "Das hat leider nicht geklappt. Ich notiere Ihre Nachricht."
        };
        FlowResponse::one(Action::speak(session, text)?)
    }
    EventPayload::UserSpeak { text, .. } if text.contains("Tschüss") => {
        FlowResponse::many([
            Action::speak(session, "Auf Wiederhören!")?,
            Action::hangup(session)?,
        ])
    }
    _ => FlowResponse::none(), // 204 No Content
};

// response.status() -> 200 | 204, response.body() -> Option<String>
# Ok::<(), sipgate_flow::Error>(())
```

`FlowResponse` refuses to build an empty array, so a handler cannot send `[]`
where it meant `204`.

## Answering over a WebSocket

Flow can also open a WebSocket **to you** and stream the same events, one JSON
message per event ([docs](https://flow.sipgate.io/api/websocket)). Because Flow
is the connector, the server half stays yours — adapt your framework's
connection to `Connection`, and `FlowSocket` (feature `websocket`) does the
rest with the same `Event`, `Action` and `FlowResponse` types:

```rust
use sipgate_flow::{Action, EventPayload, FlowResponse, FlowSocket};

async fn serve(connection: MyConnection) -> sipgate_flow::Result<()> {
    let socket = FlowSocket::new(connection);
    socket.run(|event| async move {
        let Some(session) = event.session_id() else {
            return Ok(FlowResponse::none());
        };
        match event.payload() {
            EventPayload::UserSpeak { text, .. } if text.contains("Hilfe") => {
                Ok(FlowResponse::one(Action::speak(session, "Ich verbinde.")?))
            }
            _ => Ok(FlowResponse::none()),
        }
    }).await?;
    Ok(())
}
```

`run` drives one connection (one call) until Flow closes it; a handler that
returns `FlowResponse::none()` sends nothing, and an action for an event that
accepts none (`session_end`, `user_speech_started`, …) is refused with
`Error::ActionNotAccepted` instead of being written. The inbound ceiling is
`MAX_SOCKET_MESSAGE_BYTES` and is checked before the JSON parser runs;
`MockConnection` makes a handler testable without a socket, and
`AcceptBackoff` paces the accept loop that keeps your endpoint reachable after a
dropped link.

## Answering a classic Push API call

The classic Push API is a different protocol — `application/x-www-form-urlencoded`
in, XML out — so it has its own module. `PushVerifier` enforces the content type
and the body ceiling; `PushResponse` renders the document, including the
`onAnswer`/`onHangup` subscriptions:

```rust
use sipgate_flow::push::{Dial, Gather, Play, PushAction, PushResponse, PushVerifier};

let event = PushVerifier::new().verify_and_parse(
    Some("application/x-www-form-urlencoded"),
    body, // the raw request body
)?;

let response = match event.kind() {
    sipgate_flow::push::PushEventKind::NewCall => PushResponse::new()
        .with_on_hangup("https://example.com/hangup")?
        .with_verb(PushAction::gather(
            Gather::new("https://example.com/dtmf")?
                .with_max_digits(1)?
                .with_play(Play::new("https://example.com/menu.wav")?),
        )),
    sipgate_flow::push::PushEventKind::Dtmf if event.dtmf() == Some("1") => {
        PushResponse::new().with_verb(PushAction::dial(Dial::to_number("4915799912345")?))
    }
    _ => PushResponse::new(), // a valid, empty <Response />
};

// Send `response.content_type()` ("application/xml") with `response.to_xml()`.
```

`maxDigits` and `timeout` refuse `0` because the reference documents `>= 1`; a
`Dial` refuses a sixth target, because the reference documents up to five; every
URL is an absolute `http(s)` URL without credentials, and every number is E.164.
The reference documents **no credential** for this API, so `PushVerifier` does
not pretend to authenticate a caller — protect the endpoint at the edge (an
unguessable path, a reverse proxy, an allow-list) and treat every event as
untrusted input. `docs/contracts.md` §11 records that gap.

## Calling the REST API

```rust
use sipgate_flow::{rest::Sms, OAuth2Client, ClientCredentials, ReqwestTransport, RestClient};

let auth = OAuth2Client::new(
    ReqwestTransport::new(),
    ClientCredentials::new(client_id, client_secret)?
        .with_scopes(["sessions:sms:write", "sessions:write"]),
);
let client = RestClient::new(ReqwestTransport::new(), auth)
    .with_timeout(Some(std::time::Duration::from_secs(10)));

client.send_sms(&Sms::new("s0", "4915112345678", "Ihr Code: 4242")?).await?;
```

A **Personal Access Token** is *not* a bearer token: sipgate documents it as
`Authorization: Basic base64(<token id>:<token>)`, so it has its own type:

```rust
use sipgate_flow::{PersonalAccessToken, ReqwestTransport, RestClient};

let client = RestClient::new(
    ReqwestTransport::new(),
    PersonalAccessToken::new(std::env::var("SIPGATE_TOKEN_ID")?, std::env::var("SIPGATE_TOKEN")?)?,
);
```

`StaticToken` holds an OAuth2 access token and sends `Bearer`. Empty or
colon-bearing credentials are refused at construction, and no credential appears
in any `Debug` output.

## What is modelled

* **Every documented Flow event**, typed (`EventPayload`), plus `user_barge_in`
  (published by the official TypeScript SDK only). Unknown event types are
  carried as `EventPayload::Unknown(serde_json::value::RawValue)` and unknown
  fields are preserved in `Event::extra`.
* **All eight documented Flow actions** (`speak`, `audio`, `mix_audio`,
  `hangup`, `transfer`, `barge_in`, `configure_transcription`, `send_sms`), each
  with typed inputs and validated before the request exists — including all four
  barge-in strategies and every documented TTS provider (`kugelaudio`, `azure`,
  `eleven_labs`, plus `openai` from the SDK schema).
* **The documented Flow webhook handshake**: shared secret in constant time,
  JSON-only content type, bounded event bodies, `200`/`204` response shapes.
* **The classic Push API**, end to end: all four documented events (`newCall`,
  `answer`, `hangup`, `dtmf`), every documented field (including `user[]`,
  `origCallId`, `xcid`, `diversion`, `answeringNumber` and all seven hangup
  causes), unknown events and parameters carried instead of rejected, and all
  five documented XML verbs (`Dial` with up to five targets or voicemail,
  `Play`, nested `Gather`, `Reject`, `Hangup`) plus the `onAnswer`/`onHangup`
  subscriptions. Form decoding and XML rendering are pure, bounded and
  socket-free.
* **The WebSocket transport** (`websocket` feature): the same events and actions
  as JSON messages over the connection Flow opens to your server, with ping/pong
  handling, a bounded inbound frame ceiling checked before parsing, a per-event
  action contract (`ActionNotAccepted`), and `AcceptBackoff` for the accept loop.
  No socket is needed to test a handler: `MockConnection` is the transport.
* **Outbound Flow calls** (`POST /v3/ai-flows/{id}/call`) with a typed
  `OutboundCallReceipt` for the documented `callSid` response.
* **Sixteen REST v2 operations** covering SMS, fax (send + resend), outbound
  calls (classic and Neo PBX), voicemail playback, IVR/voicemail recording,
  call listing, hangup, DTMF, announcements, recording, hold, mute and transfer.
* **OAuth2 client credentials** with an expiry-aware token cache behind a
  `Mutex` (no `static mut`, no globals), a 60 s refresh margin, and one forced
  refresh on `401`.

Text, digits, phone numbers, languages, vocabulary, timeouts, volumes, audio
containers and URL/path values are validated on the way out. Audio bytes are
checked for the format the service actually plays (16 kHz mono 16-bit PCM for
Flow, 8 kHz for REST announcements) rather than uploaded and silently dropped.

## Resilience

* `408`, `425`, `429` and retryable `5xx` answers on an **idempotent** request
  are retried with exponential backoff and equal jitter (default 3 attempts,
  250 ms doubling to an 8 s ceiling). `Retry-After` is honoured and clamped to
  the ceiling. Permanent `501` and `505` answers are terminal for every method.
* A retryable `5xx`, timeout or reset after a `POST` is **not** retried: it is
  `Error::Ambiguous`. See the delivery contract below.
* The library **never sleeps**. It awaits a caller-supplied `Sleeper`, so pacing
  and therefore cancellation stay with you:

  ```rust
  use sipgate_flow::FnSleeper;
  let client = client.with_sleeper(FnSleeper::new(tokio::time::sleep));
  ```

  `#[tokio::main] async fn main()` plus `select!` on a shutdown token makes the
  wait cancellable; nothing is spawned in the background.
* `401` refreshes the token **once** and is terminal the second time. Other 4xx
  are terminal immediately.
* Per-request timeouts are configurable on every client.
* Outbound calls are never retried — dialling twice would ring twice, and a 5xx
  on the call `POST` is reported as `Error::Ambiguous`.

### Delivery contract

sipgate documents no idempotency key on any endpoint, so a repeat is never
free. Every request ends up in exactly one of three classes
(`classify` is the pure function that decides it):

| Class | When | What the client does |
| --- | --- | --- |
| **at-least-once** | `GET`, `PUT`, `DELETE` failing with retryable `5xx`; any method failing with `408`, `425` or `429`; a failure *before* the write (DNS, TCP, TLS) | retries, bounded by `RetryPolicy` |
| **ambiguous** | `POST` answered with retryable `5xx`, or a `POST` whose connection died after the request was written (timeout, reset) | returns `Error::Ambiguous` immediately, with `Error::status()` when a status arrived |
| **terminal** | permanent `501`/`505`, any other `4xx` | returns `Error::Api` |

`Error::is_retryable()` is `false` for an ambiguous outcome on purpose: the SMS,
fax, recording or call may already exist, and only you know how to check.
`Error::is_ambiguous()` is the flag to branch on, and the message names the
method that was not repeated. Reconcile with your own ledger — an id you stored
before the call, or the provider's report — never by retrying blindly.

The 401 path is the exception that proves the rule: `401` is emitted before the
request is executed, so the token is refreshed once and the request is repeated
even for `POST`.

## Permissive in, strict out

`camelCase` and `snake_case`, reordered fields, unknown fields, unknown event
types, unknown enum values (`Other(String)`), missing optional fields and empty
bodies are all handled without failing the parse. Duplicate **known** keys are a
typed error instead of a guess. A missing `session.id` parses (so the event can
be logged) but can never be addressed: `Action` builders refuse an empty id, a
`/` or a control character.

## Where the rest lives

Every surface sipgate documents and this crate does not model yet is an open
issue, so a caller can see whether their case is covered instead of reading a list
of decisions — and `tests/docs.rs` fails the build if a gap is written down without
an issue behind it:

* **REST v2 account administration** (devices, contacts, history, phonelines,
  numbers, …) — [#12](https://github.com/floffel/sipgate-flow/issues/12).
  Documented endpoints, not modelled yet.
* **v3 webhook and TTS configuration** (`PUT /ai-webhooks` and the TTS provider
  catalogue) — [#15](https://github.com/floffel/sipgate-flow/issues/15).
  Documented paths, not modelled yet.
* **v3 account, device and phoneline inventory** (accounts, devices,
  phonelines; ai-agents and the playground are other products) —
  [#15](https://github.com/floffel/sipgate-flow/issues/15). Documented paths,
  not modelled yet.

Two surfaces really are absent upstream, which is the only kind of exclusion the
standing order allows: delivery through the Flow "external API POST" (no path,
method or body envelope is documented anywhere — see `docs/contracts.md` §7.1) and
fax, voicemail, recording or DTMF *as Flow actions* (they are not in the Flow
action catalogue; the REST v2 operations that do exist are implemented here —
§7.8).

## Examples

Three runnable examples, all offline (`cargo run --example <name>`):

* `flow_webhook` — verifies `X-API-TOKEN`, parses a `user_speak`, answers with
  two actions, and shows the 204 `session_end` must get.
* `push_webhook` — decodes a `newCall`, answers with a `<Gather>` that plays a
  prompt, forwards the collected digit, and shows the JSON refusal.
* `rest_dry_run` — drives `RestClient` against a recording `Transport` and
  prints the request the crate would send; a real call is one
  `ReqwestTransport::new()` away.

CI runs `flow_webhook` and `rest_dry_run` and builds every example without
default features, so the quickstarts cannot drift away from the API.

## Tests

```bash
cargo test                        # 495 tests + 492 doctests (default features)
cargo test --all-features         # 526 tests + 515 doctests (adds the websocket feature)
cargo test --no-default-features  # 472 tests + 489 doctests (no reqwest, no websocket)
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo +nightly fuzz run parse_event   # fuzz/ — six named targets
cargo llvm-cov --all-features --summary-only
```

* **Fixtures** (`tests/fixtures/`) are the documented payloads verbatim; the
  event tests fail if the model drifts from the published wire format.
* **Property tests** (`tests/properties.rs`): arbitrary JSON, arbitrary bytes
  and arbitrary form bodies never panic the parsers; documented events
  round-trip and render idempotently; a validated `Dial` renders exactly its
  digits; base64 and WAV round-trip; backoff stays bounded and jittered;
  `Retry-After` never panics.
* **The classic Push API** (`tests/push.rs`): every fixture is a documented
  request body; the four events decode with their fields, the five XML verbs
  (and `onAnswer`/`onHangup`) render exactly as documented, and each limit is
  pinned by the just-inside/just-outside pair — five versus six dial targets,
  seven/fifteen versus six/sixteen E.164 digits, `1` versus `0` for `maxDigits`
  and `timeout`, the URL length limit versus one byte over, the 64 KiB body
  ceiling versus one byte over, and a reader that never ends. The test plays the
  HTTP framework, so no socket is involved.
* **The WebSocket transport** (`tests/websocket.rs`, `websocket` feature): every
  documented event arrives from a text *and* a binary frame, pings are answered,
  actions render exactly as the webhook body does, the frame ceiling is pinned
  on both sides (`limit` / `limit - 1`, `MAX` / `MAX + 1`, `0` and `MAX + 1`
  refused), an action for an actionless event is refused before the wire, and
  arbitrary frames are proved panic-free with `proptest`. The peer is
  `MockConnection`, not a socket.
* **Documentation guards** (`tests/docs.rs`): the gap list in the README and
  `docs/contracts.md` must link a tracked issue, may never be described as an
  exclusion, and both documents have to list the same number of gaps.
* **Edge cases**: empty and whitespace bodies, non-object JSON, truncated JSON,
  duplicate known keys, wrong field types, unicode/NUL, body-size boundaries,
  over-long phone numbers, path-escape attempts, `NaN` volumes, wrong WAV
  formats, `Retry-After` clamping and budget exhaustion.
* **Concurrency**: one client hammered from 32 tasks (`Send + Sync` enforced by
  the compiler at the call site).
* **Fuzz targets** (`fuzz/`): `parse_event` (webhook bodies), `parse_socket`
  (raw WebSocket frames through `FlowSocket`), `parse_token` (token responses),
  `parse_rest` (the `GET /calls` envelope and the outbound `callSid` body),
  `parse_base64` (the decoder) and `parse_push` (Push API form bodies), each
  asserting that whatever parses re-parses to the same value.
* **Every test but one file runs against `MockTransport`** (`tests/common/`).
  `tests/http_transport.rs` is the exception: it binds a `TcpListener` on
  `127.0.0.1` to exercise the `reqwest` adapter itself (verbs, both auth
  schemes, JSON and form bodies, timeouts, truncated bodies). Nothing reaches
  the network.
* **Coverage**: **96.6 % of lines, 97.0 % of regions, 97.6 % of functions**
  (`cargo llvm-cov --all-features`; the figure moves by a few tenths between
  toolchains, the WebSocket module is at 100 % of its lines, and the Push
  modules are above 93 % of lines each). CI fails below 95 %.

## Versioning

Semantic Versioning 2.0.0, one version for both halves of the crate (`flow` and
`rest` are released together), and an entry in [`CHANGELOG.md`](CHANGELOG.md) for
every change a caller can observe. The version bump and the changelog entry land
on the commit that gets tagged — a tag can never publish something the changelog
does not describe.

While the major version is `0`, a **minor** bump may break and a **patch** never
does. From `1.0.0` on, ordinary SemVer applies. What counts as breaking here:

* removing or renaming a public item;
* adding a required field, or a variant to an enum that is *not*
  `#[non_exhaustive]`;
* **tightening a validation rule** — a value the crate accepted last week is a
  rejected call today. Loosening a rule is a minor change.

Every public enum — provider payloads, actions, `Error` — and every struct a
caller could otherwise build with a struct literal (`Request`, `Session`,
`WavFormat`) is `#[non_exhaustive]`: a new sipgate event type, error or field
is an addition, not a break, and a downstream `match` already carries a `_` arm.
`tests/public_surface.rs` re-derives that decision from `src/` on every run.

**MSRV: Rust 1.89.** It is declared as `rust-version` in `Cargo.toml`, so an
older toolchain refuses the build with a clear message instead of failing halfway
through, and the `msrv` CI job runs the whole suite on exactly that version.
Raising the MSRV is a minor release, never a patch.

## License

Licensed under either of Apache-2.0 or MIT at your option.
