# sipgate-flow

Typed, tolerant client for **sipgate flow** and the **sipgate REST API v2**.

sipgate ships two JSON APIs that are easy to mix up, and 0.1 mixed them up. This
crate keeps them apart:

| Half | What it does | Docs |
| --- | --- | --- |
| `flow` | Your webhook **receives** events (`session_start`, `user_speak`, `dtmf_received`, …) and **returns** actions (`speak`, `audio`, `transfer`, …) in the response. There is no separate endpoint to post an action to. | [flow.sipgate.io/api](https://flow.sipgate.io/api/) |
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

let response = match event.payload() {
    EventPayload::SessionStart { transfer_failed_reason: Some(reason), .. } => {
        let text = if reason.is_worth_retrying() {
            "Die Leitung ist besetzt. Soll ich es bei einer Kollegin versuchen?"
        } else {
            "Das hat leider nicht geklappt. Ich notiere Ihre Nachricht."
        };
        FlowResponse::one(Action::speak(event.session_id().unwrap_or_default(), text)?)
    }
    EventPayload::UserSpeak { text, .. } if text.contains("Tschüss") => {
        FlowResponse::many([
            Action::speak(event.session_id().unwrap_or_default(), "Auf Wiederhören!")?,
            Action::hangup(event.session_id().unwrap_or_default())?,
        ])
    }
    _ => FlowResponse::none(), // 204 No Content
};

// response.status() -> 200 | 204, response.body() -> Option<String>
# Ok::<(), sipgate_flow::Error>(())
```

`FlowResponse` refuses to build an empty array, so a handler cannot send `[]`
where it meant `204`.

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
  carried as `EventPayload::Unknown(serde_json::Value)` and unknown fields are
  preserved in `Event::extra`.
* **All eight documented Flow actions** (`speak`, `audio`, `mix_audio`,
  `hangup`, `transfer`, `barge_in`, `configure_transcription`, `send_sms`), each
  with typed inputs and validated before the request exists — including all four
  barge-in strategies and every documented TTS provider (`kugelaudio`, `azure`,
  `eleven_labs`, plus `openai` from the SDK schema).
* **The documented Flow webhook handshake**: shared secret in constant time,
  JSON-only content type, 1 MiB body ceiling, `200`/`204` response shapes.
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

* `429` and `5xx` on an **idempotent** request are retried with exponential
  backoff (default 3 attempts, 250 ms doubling to an 8 s ceiling).
  `Retry-After` is honoured and clamped to the ceiling.
* A `5xx`, timeout or reset after a `POST` is **not** retried: it is
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
| **at-least-once** | `GET`, `PUT`, `DELETE` failing with `5xx`; any method failing with `429`; a failure *before* the write (DNS, TCP, TLS) | retries, bounded by `RetryPolicy` |
| **ambiguous** | `POST` answered with `5xx`, or a `POST` whose connection died after the request was written (timeout, reset) | returns `Error::Ambiguous` immediately, with `Error::status()` when a status arrived |
| **terminal** | any other `4xx` | returns `Error::Api` |

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

* **The classic Push API** (`event=newCall`, XML `<Dial>`/`<Gather>` responses) —
  [#10](https://github.com/floffel/sipgate-flow/issues/10). Form-encoded in, XML
  out: its own module, with the same validation and webhook-verification
  discipline as Flow.
* **The WebSocket transport** — [#11](https://github.com/floffel/sipgate-flow/issues/11).
  Flow connects *to you*, so the client half needs a server half; the event and
  action type trees are transport agnostic and work there unchanged.
* **REST v2 account administration** (devices, contacts, history, phonelines,
  numbers, …) — [#12](https://github.com/floffel/sipgate-flow/issues/12).
  Documented endpoints, not modelled yet.
* **The rest of the v3 surface** (`PUT /ai-webhooks`, the TTS provider catalogue,
  accounts, devices; ai-agents and the playground are other products) —
  [#15](https://github.com/floffel/sipgate-flow/issues/15).

Two surfaces really are absent upstream, which is the only kind of exclusion the
standing order allows: delivery through the Flow "external API POST" (no path,
method or body envelope is documented anywhere — see `docs/contracts.md` §7.1) and
fax, voicemail, recording or DTMF *as Flow actions* (they are not in the Flow
action catalogue; the REST v2 operations that do exist are implemented here —
§7.8).

## Tests

```bash
cargo test                        # 217 integration + 341 doctests
cargo test --no-default-features  # same, without reqwest
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo +nightly fuzz run parse_event   # fuzz/ — three named targets
cargo llvm-cov --all-features --summary-only
```

* **Fixtures** (`tests/fixtures/`) are the documented payloads verbatim; the
  event tests fail if the model drifts from the published wire format.
* **Property tests** (`tests/properties.rs`): arbitrary JSON and arbitrary bytes
  never panic the event parser; documented events round-trip and render
  idempotently; base64 and WAV round-trip; backoff stays bounded and monotonic;
  `Retry-After` never panics.
* **Documentation guards** (`tests/docs.rs`): the gap list in the README and
  `docs/contracts.md` must link a tracked issue, may never be described as an
  exclusion, and both documents have to list the same number of gaps.
* **Edge cases**: empty and whitespace bodies, non-object JSON, truncated JSON,
  duplicate known keys, wrong field types, unicode/NUL, 1 MiB payloads,
  over-long phone numbers, path-escape attempts, `NaN` volumes, wrong WAV
  formats, `Retry-After` clamping and budget exhaustion.
* **Concurrency**: one client hammered from 32 tasks (`Send + Sync` enforced by
  the compiler at the call site).
* **Fuzz targets** (`fuzz/`): `parse_event` (webhook bodies), `parse_token`
  (token responses) and `parse_rest` (the `GET /calls` envelope and the outbound
  `callSid` body), each asserting that whatever parses re-parses to the same
  value.
* **Every test but one file runs against `MockTransport`** (`tests/common/`).
  `tests/http_transport.rs` is the exception: it binds a `TcpListener` on
  `127.0.0.1` to exercise the `reqwest` adapter itself (verbs, both auth
  schemes, JSON and form bodies, timeouts, truncated bodies). Nothing reaches
  the network.
* **Coverage**: **98.1 % of lines, 99.5 % of regions, 99.1 % of functions**
  (`cargo llvm-cov --all-features`). CI fails below 95 %.

## License

Licensed under either of Apache-2.0 or MIT at your option.
