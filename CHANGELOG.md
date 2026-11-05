# Changelog

All notable changes to this crate are recorded here, newest first.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 reading described in the README section *Versioning*.

## [Unreleased]

### Fixed

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
