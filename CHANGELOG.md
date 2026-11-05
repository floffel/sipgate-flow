# Changelog

All notable changes to this crate are recorded here, newest first.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 reading described in the README section *Versioning*.

## [Unreleased]

### Added

* Part of the **v3 AI webhook and TTS voice surface** (#15): `FlowClient`
  now models `PUT`/`GET /v3/ai-webhooks` with the typed
  `AiWebhookSettings` body/response and `GET /v3/tts/voices` with `TtsVoice`
  entries from the documented `{"items": [...]}` catalogue. The webhook URL is
  validated as absolute `https://` before it can reach the wire; the voice
  catalogue accepts both the current bare-id entries and the richer object
  shape used by the adjacent frontdesk catalogue, keeps unknown fields in
  `raw()`, and refuses an empty catalogue instead of returning a misleading
  success. The remaining v3 account/device/phoneline inventory stays tracked in
  #15.
* The **core REST v2 account-administration reads** (#12): typed models and
  `RestClient` methods for the four documented families previewed in the gap
  list — `device` (`GET /v2/devices/{deviceId}`), `contacts` / `contact`
  (`GET /v2/contacts`, `GET /v2/contacts/{contactId}`), `history`
  (`GET /v2/history`) and `phonelines` (`GET /v2/phonelines`). Path parameters
  reuse the crate's `path_segment` gate, list responses accept the documented
  `{"items": [...]}` envelope tolerantly, and every typed enum carries unknown
  provider values verbatim instead of failing the decode. The full REST v2
  administration surface, including all write and nested setting endpoints,
  remains tracked as open issue #12.
* The **classic Push API** (<https://en.sipgate.io/push-api/api-references>),
  promoted from the README's gap list (#10). Its own `push` module: all four
  documented events (`newCall`, `answer`, `hangup`, `dtmf`) decoded from
  `application/x-www-form-urlencoded` with the same tolerance as Flow — unknown
  events and parameters are carried, `camelCase` and `snake_case` name the same
  parameter, and a duplicate *scalar* parameter is a typed error instead of a
  guess. The five documented XML verbs are rendered as a `<Response>`: `Dial`
  (up to five targets or voicemail, `callerId`, `anonymous`), `Play`, `Gather`
  (with nested `Play`), `Reject` and `Hangup`, plus the `onAnswer`/`onHangup`
  subscriptions. `PushVerifier` bounds the body (`MAX_PUSH_BODY_BYTES`, 64 KiB,
  checked before the form is decoded) and refuses a foreign content type; the
  reference documents no credential, so it invents none (§7.10 of
  `docs/contracts.md`). Every documented limit and every crate ceiling is
  pinned by a just-inside/just-outside pair, the form decoder and the XML
  escaper have property tests, and the whole module works without a socket.
* `Error::Form` (with `Error::form`) reports a Push API body that is not
  decodable form data, carries no `event` parameter, or repeats a scalar
  parameter. Like the other parse errors it names the parameter, never the
  value, and is terminal.

* The **Flow WebSocket transport** (<https://flow.sipgate.io/api/websocket>),
  behind the new `websocket` feature. Flow connects *to* the application, so the
  crate ships the server half and leaves the socket to the caller: implement
  `Connection` for your framework's web socket, and `FlowSocket` turns incoming
  frames into the same typed `Event`s the webhook path produces and writes
  `Action`s back in the same flat JSON the webhook body uses. `run` drives one
  connection (one call) until Flow closes it; `send_action` sends an unsolicited
  action, which this transport allows. Pings are answered with pongs, an
  inbound frame is bounded by `MAX_SOCKET_MESSAGE_BYTES` *before* the JSON parser
  runs (the ceiling is configurable within `1..=MAX`, and `0` or more than the
  parser ceiling is refused), and an action for an event that accepts none is
  refused with the new `Error::ActionNotAccepted` instead of being written.
  `MockConnection` is an in-memory transport, so handlers are testable without a
  socket, and `AcceptBackoff` paces the accept loop that reconnects after a
  dropped link (bounded, jittered, never giving up). The handshake carries no
  documented authentication — `docs/contracts.md` §3.2 records what the page
  documents and §7.9 the gap — so every security check stays where the socket is
  accepted. The `WebSocket` entry left the "Where the rest lives" list.
* `Error::Socket` (with `Error::socket`, `Error::socket_terminal` and
  `Error::socket_with_source`) reports a failed link with its cause attached and
  `is_retryable()` telling the caller whether a new connection is worth trying.
  It never re-sends a frame: a lost action is reported, not repaired.
* The **full REST v2 history resource** (#166): typed `RestClient` methods for
  `GET /v2/history`, `GET /v2/history/export`, `GET`/`DELETE`/`PUT`
  `/v2/history/{entryId}`, `DELETE`/`PUT` `/v2/history`, and the deprecated
  archive/note/read updates. `HistoryQuery` validates the documented pagination
  bounds before the wire, accepts the documented filters (types, directions,
  starred state, date range, include-all-users and connection IDs), and sends
  them as the repeated query parameters Swagger documents. Response decoding
  remains permissive, including `total_count`/`totalCount`, while single-entry
  and bulk write requests carry typed bodies.

* The **REST v2 `devices` resource** (#164, split from #12): typed models and
  `RestClient` methods for the documented `/devices` surface — the device
  list with its `type` filter, the create-family endpoints for register,
  mobile and external devices, the settings writes (alias, DND/emergency
  address, caller ID, password reset, external display/target number, local
  prefix, single-row display, tariff announcement), the contingents read and
  the SIM activate/deactivate/order operations. Path and query parameters and
  every body field run through the crate's `validate::` gates before the
  wire, response models decode camelCase and snake_case with unknown fields
  ignored and unknown enum values carried verbatim, and request builders
  refuse values the schema does not document instead of sending them.
* The **REST v2 phonelines resource** (#167): the full documented surface under
  `/{userId}/phonelines` is now typed, including phoneline CRUD and alias
  updates, anonymous-call blocking, routed devices, forwardings, numbers,
  parallel forwardings, sipgate.io settings and logs, voicemail settings,
  greetings and transcription settings. Path parameters and E.164 destinations
  are validated before the wire; list responses use the permissive `{"items":
  [...]}` envelope; and request builders cover the schema's documented fields
  and limits.

### Fixed

* The retry module now records the exact reuse audit decision: `httpdate` already
  owns HTTP-date `Retry-After` parsing, while `backoff` 0.4 cannot replace the
  rest because it is unmaintained, would fail the advisory gate, and would
  replace the runtime-free, pure `RetryPolicy`/`Sleeper` contract with stateful
  or runtime-coupled retry machinery.
* The `truncate_body` documentation no longer claims the helper bounds the
  transport read: it documents that it caps the string copied into an error
  message at 512 bytes by byte length, backing up to a UTF-8 boundary. The
  exact-limit, one-past-limit and multibyte boundary cases now have tests.
* The `OAuth2Client` token cache is now single-flight. Concurrent cache misses
  no longer each call the token endpoint: the first miss starts the request and
  every other miss waits for it, so `N` simultaneous cold reads cost exactly one
  token request instead of up to `N`. The cache read and the fetch reservation
  share one lock (never held across the `.await`), a failed fetch releases its
  waiters to retry, and `force_refresh` still bypasses the gate because a
  rejected credential needs a genuinely new token. This removes the
  intermittently failing
  `thirty_two_tasks_share_one_token_cache_without_corruption` test, whose bound
  is now tightened to exactly one request.
* The crate-root "Calling the REST API" section now ships a runnable example. An in-memory `Transport` drives `RestClient::send_sms` and asserts the URL that goes out, so the renderer-free path is executed by the doctest runner (including under `--no-default-features`); the `reqwest` half is split out so only the `ReqwestTransport` lines sit behind the `http` feature instead of the whole example compiling away.
* The `reqwest` transport now bounds the response body instead of reading it
  whole and cloning it. `ReqwestTransport` refuses an oversized
  `Content-Length` before reading, streams a body without one through
  `reqwest::Response::chunk`, and returns the typed `Error::BodyTooLarge` once
  the ceiling is crossed, so a hostile or broken endpoint can no longer choose
  the transport's allocation. The default is
  `DEFAULT_MAX_RESPONSE_BODY_BYTES` (1 MiB, mirroring the webhook ceiling) and a
  caller can tighten it with `ReqwestTransport::with_max_body_bytes`.
* `RetryPolicy::delay(0, ...)` no longer schedules a full backoff step. The
  parameter is documented as completed *failures*, so zero completed failures
  now returns `None` instead of treating the first caller attempt index as an
  already-failed try; the boundary is pinned in tests for 0, 1,
  `max_attempts - 1`, `max_attempts` and `u32::MAX`.
* The crate-root REST example now states the PAT wire form accurately again:
  `PersonalAccessToken` sends `Authorization: Basic base64(<token id>:<token>)`
  and links to `transport::Security::Basic` for the same contract.
* `Response::json` no longer synthesises an empty object for a body that never
  arrived. A body that is empty or only ASCII whitespace is now `Value::Null`
  for the statuses that forbid a body (`204`/`205`, via the new
  `Response::is_no_content`) and a typed `Error::EmptyBody` for every other
  status, so a truncated or proxy-stripped `200` fails closed instead of
  parsing to a `{}` whose every field lookup yields `Null`.
* The minimal configuration (`--no-default-features`) now builds clean under
  `-D warnings`: the crate-internal transport-error constructor is `http`-gated
  (nothing outside the `reqwest` adapter calls it), and the two intra-doc links
  to `ReqwestTransport` are plain code spans, so `cargo doc` no longer fails on
  an unresolvable link when the feature is off. Both defects were invisible to
  CI, which only ran clippy and rustdoc for the full feature set.
* The crate-root tolerance contract (unknown fields, unknown event types,
  camelCase and snake_case keys, and "validate before sending") now has
  executable proof. Runnable doctests on the crate root pin each claim, and a
  property test drives arbitrary unknown fields through a known event to prove
  they survive in `Event::extra` and round-trip unchanged.
* `Response` no longer loses header data. The `reqwest` adapter turned a
  non-UTF-8 header value into `""` (present but empty) and collapsed repeated
  headers into one `BTreeMap` entry, so `header("retry-after")` could report
  `Some("")` for a value that was dropped and only the last of several
  `Set-Cookie` headers survived. Headers are now kept as raw byte pairs in wire
  order: `header` returns `None` for a non-UTF-8 value instead of an empty
  string, and `header_all` / `header_bytes` / `headers_bytes` expose every
  value. `Response::new` and `header` stay source-compatible.
* Status classification now separates permanent 5xx answers from ambiguous
  ones: `501` and `505` are terminal instead of being reported as possibly
  applied after a `POST`, while `408` and `425` are retryable because they mean
  nothing was processed. The refined table is pinned in the property and
  delivery tests.
* `WebhookVerifier::verify_headers` admits the webhook shared secret from a
  request's headers regardless of how the framework spells the header name.
  HTTP header names are case-insensitive, but the exported `SECRET_HEADER` /
  `SECRET_HEADER_LEGACY` constants are lowercased, so a handler indexing a map
  that preserved `X-API-TOKEN` got `None` and every request failed closed with
  `MissingSecret`. The new method matches both documented names with
  `eq_ignore_ascii_case`, rejects a request whose two present spellings
  disagree, and keeps the constant-time value comparison.
* `validate::language_tag` now checks the documented BCP-47 *shape* instead of
  only the alphabet. Structurally invalid tags that previously slipped through
  (`"-"`, `"en-"`, `"en--US"`, `"1234"`, a lone 35-character subtag, and
  friends) are refused before the TTS or transcription request is built.
* The flagship crate example no longer teaches failure-to-default. It used
  `event.session_id().unwrap_or_default()`, silently substituting an empty
  session id and returning `200` as if the action were valid. The example now
  uses `let Some(session) = event.session_id() else { return Ok(FlowResponse::none()) };`,
  and the doctest actually executes both branches (present and missing session
  id) instead of only the branch that never needed the fallback. Action builders
  already reject an empty session id with `Error::Validation { field:
  "session_id", .. }`, which a regression test now pins.
* `Retry-After` now accepts both documented forms. HTTP-date values are
  converted against the crate `Clock` and saturate at zero when the date has
  passed; delta-seconds above `u64` and present-but-unparseable values fail
  closed to the caller's ceiling instead of silently falling back to the
  shortest backoff step.
* Webhook content-type and body-boundary behavior now has explicit proof:
  `is_json_content_type` is covered by property tests (ASCII-case idempotence,
  arbitrary `application/json` parameters, and no-slash rejection), the
  buffered body limit is pinned at exactly `max` / `max + 1`, and the
  verification order is pinned so a wrong secret is refused before content-type
  and size checks.
* The provenance pointer to `docs/contracts.md` is now a real link in the
  rendered docs: the module-level "see the exact source of every shape" claims
  in `flow`, `rest` and the crate root linked the file as an inert code span,
  which is unclickable on docs.rs. They now point at the file by repository URL.
* Transport `Debug` redaction now covers the common webhook, HMAC and OAuth
  spellings that were missing from the credential-field list: `signature`,
  `credential`, `auth`, `verifier`, `code` and `cert`. These names fail closed,
  so ambiguous fields such as `error_code` are hidden too instead of risking a
  log-time secret leak.
* `validate::non_empty` now enforces the byte ceilings its documentation
  promised. The public action and REST builders pass the documented limits for
  their fields, so a multi-megabyte caller string is refused before it is
  copied into a request body.
* Retry pacing now has a hard `MIN_RETRY_DELAY` floor. `with_base_delay`,
  `with_max_delay`, local backoff and `Retry-After` values can no longer produce
  a zero wait, so a misconfigured policy or a zero hint cannot hammer a peer
  that is already rate-limiting the caller.
* `Error::Ambiguous` now keeps the response evidence that resolves the
  ambiguity: `Error::ambiguous_with_response` stores the bounded, sanitised
  body and headers (minus `Authorization`, `Cookie` and `Set-Cookie`), and
  `Error::ambiguous_body` / `Error::ambiguous_header` expose them. A caller
  handed a 5xx or timeout after a `POST` can now check whether sipgate already
  created the SMS or call instead of guessing. The crate docs describe the
  concrete check.
* Event parsing now rejects bodies above `MAX_EVENT_BODY_BYTES` before
  deserialising, and unknown event types keep their raw JSON without building
  the duplicate `Value` trees that the old parser materialised.
* Error cause chains are no longer flattened to `String`:
  `Error::TokenResponse` and `Error::Transport` keep the underlying
  `serde_json`/`reqwest` error as their `source`, and the blanket
  `#[from] serde_json::Error` is gone. Parsing uses `Error::json_parse` while an
  outbound encode failure is reported as the distinct `Error::JsonEncode`, so a
  request body this crate emitted can no longer be mislabelled as an invalid
  remote payload.
* Transport failures with an unknown write phase now fail closed:
  `Error::transport` returns an ambiguous outcome instead of a retryable one,
  while the new `Error::transport_before_write` marks DNS, TCP connect and TLS
  failures that provably happened before the request was written as retryable.
  This keeps `Error::is_retryable()` and `Error::is_ambiguous()` from
  disagreeing on timeouts/resets after a request may have been written.
* A token response whose `expires_in` does not fit the cache clock no longer
  panics the process: `Token::from_json` refuses a lifetime above the new
  `auth::MAX_TOKEN_LIFETIME` (24 hours) with `Error::TokenResponse`, and the
  cache computes the expiry with `checked_add`, so an unusable value becomes a
  typed error instead of an overflow panic in `Duration` addition.
* `WebhookVerifier::verify_reader` bounds body reads before parsing, returning
  `Error::BodyTooLarge` as soon as `max_body_bytes + 1` bytes have been
  observed. The existing buffered `verify_and_parse` path now documents that it
  only bounds parsing work after the framework has collected the body.
* `WebhookVerifier::with_max_body_bytes` now returns `Result<Self>` and accepts
  only `1..=DEFAULT_MAX_BODY_BYTES`. A configured `0` is rejected at
  construction instead of turning every non-empty webhook into a
  `BodyTooLarge` failure, and values above the default cannot make the bounded
  reader's limit unbounded.
* The `flow` facade (`sipgate_flow::flow::*`) now re-exports the full public
  surface of its submodules, including the `client` types, the `webhook`
  constants and helper, and the shared `Error`/`Result` a failure path matches
  on. `tests/flow_facade.rs` pins the promise at compile time so a type added
  to a submodule and forgotten here fails the build instead of drifting out of
  the facade unnoticed.
* The **v3 TTS catalogue and synthesis surface** (#169): `FlowClient` now models
  `GET /v3/tts` (`tts_settings`) as typed `TtsSetting` entries, `POST /v3/tts`
  (`synthesize`) with the validated `SynthesizeRequest`, `POST /v3/tts/stream`
  (`synthesize_stream`) returning validated base64 `SynthesizedAudio`, and
  `GET /v3/ai-agents/{agentId}/voices` (`agent_voices`) as `AgentVoices` with a
  `CurrentVoice`. The request builders enforce the documented character and
  id-shape limits before the wire, decoding stays permissive (unknown fields
  ignored, unknown enum values carried, both `camelCase` and `snake_case`
  accepted), and a `5xx` after the non-idempotent synthesis `POST` is reported as
  `Error::Ambiguous` rather than retried.

## [0.1.0] — not yet published

### Added

* The Flow webhook half: a typed event for every documented event type, plus
  `user_barge_in`; an unknown type is carried as `EventPayload::Unknown` and
  unknown fields survive in `Event::extra` instead of failing the parse.
* `WebhookVerifier`: shared secret compared in constant time, JSON-only content
  type, 1 MiB body ceiling, and `200`/`204` response shapes.
* All eight documented Flow actions with typed builders (including all four
  barge-in strategies and every documented TTS provider), validated before the
  request exists.
* Outbound Flow calls (`POST /v3/ai-flows/{id}/call`) with a typed
  `OutboundCallReceipt` for the documented `callSid` response.
* Sixteen REST v2 operations: SMS, fax (send and resend), outbound calls
  (classic and Neo PBX), voicemail playback, IVR/voicemail recording, call
  listing, hangup, DTMF, announcements, recording, hold, mute and transfer.
* OAuth2 client credentials with an expiry-aware token cache behind a `Mutex`
  and exactly one forced refresh on `401`; `PersonalAccessToken` sends the
  documented `Basic` header instead of a bearer token.
* `Transport` as a trait with a `reqwest` adapter behind the default-on `http`
  feature, a recording `MockTransport` for tests, and caller-supplied timeouts.
* Retry policy for idempotent requests (`429`, `5xx`, exponential backoff,
  `Retry-After` honoured), with pacing delegated to a caller-supplied `Sleeper`
  so the library never sleeps and every wait stays cancellable.
* `Error::Ambiguous` for a non-idempotent request whose outcome is unknown; the
  delivery contract is documented in the README.
* Audio validation for the formats the service actually plays, and a WAV
  header check that refuses a payload its own header cannot describe.
* `docs/contracts.md`: every shape cited with its source, and the ones that stay
  unverifiable listed instead of assumed.
* Two runnable offline examples (`flow_webhook`, `rest_dry_run`), executed by CI.

### Changed

* The whole public surface is `#[non_exhaustive]` where a caller could
  otherwise build it with a struct literal: `Request`, `Session` (which gains
  `Session::new`) and `WavFormat` join the payload enums, so a new field is
  never a breaking release. `tests/public_surface.rs` derives that decision
  from `src/` and fails when a new public type forgets it.
* Parsing is permissive in the direction the wire drifts: `camelCase` and
  `snake_case`, reordered and unknown fields, unknown enum values. Duplicate
  known keys are a typed error rather than a guess.

### Security

* No credential appears in any `Debug` output; secrets compare in constant time
  (as digests, so the length does not leak); sizes are validated before memory
  is allocated.

### Notes

* The version is deliberately not published: the wire contracts are verified
  against public documentation but not yet against a sandbox ([#2]).
* MSRV is Rust 1.89, tested by the `msrv` CI job; the policy lives in the README.

[Unreleased]: https://github.com/floffel/sipgate-flow/commits/main
[#2]: https://github.com/floffel/sipgate-flow/issues/2
