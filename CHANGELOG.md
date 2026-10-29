# Changelog

All notable changes to this crate are recorded here, newest first.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and the version numbers follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 reading described in the README section *Versioning*.

## [Unreleased]

Nothing yet.

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
