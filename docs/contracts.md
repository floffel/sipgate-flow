# Verified contracts

Every shape this crate accepts or sends, with the public document it came from.
Retrieved **2026-10-24**. If a shape is not in this file it is not modelled.

Rule for this document: a shape is **verified** only when a public sipgate page
(or the public Swagger document, or the realm's discovery document) states it.
Anything I could not confirm is listed under [Unverified](#unverified), and the
code treats it accordingly — never as if it were a fact.

---

## 0. Three products, only two of which this crate speaks

| Product | Protocol | Auth | In this crate |
| --- | --- | --- | --- |
| **sipgate flow** (`flow.sipgate.io`) | JSON both ways; actions go in the **webhook response** | shared secret in `X-API-TOKEN` | `flow::*` |
| **sipgate REST API v2** (`api.sipgate.com/v2`) | JSON in/out over REST | OAuth2 bearer / PAT | `rest::*` |
| **sipgate.io Push API** (classic) | `application/x-www-form-urlencoded` in, **XML** out | — | **not modelled**, see §8 |

The 0.1 stub conflated them: it parsed `{"event":"answered","callId":…}`
(shaped after the Push API), emitted `{"action":"tts"}` (a name neither product
uses), and posted to `{base}/calls/{id}/actions` — a path that exists in
**neither** API. All three assumptions are gone.

---

## 1. Flow events — verified

Source: <https://flow.sipgate.io/api/events> (event table) plus one page per
event. Every event carries `type` and `session`; `session.id` is the value an
action must echo back as `session_id`.

| `type` | Source page | Fields modelled | Fixture |
| --- | --- | --- | --- |
| `session_start` | [/api/events/session-start](https://flow.sipgate.io/api/events/session-start) | `session.{id,account_id,phone_number,direction,from_phone_number,to_phone_number}`, `transfer_failed_reason?` | `tests/fixtures/flow/session_start*.json` |
| `user_speech_started` | [/api/events/user-speech-started](https://flow.sipgate.io/api/events/user-speech-started) | `session` only; WebSocket-only event | `user_speech_started.json` |
| `user_speak` | [/api/events/user-speak](https://flow.sipgate.io/api/events/user-speak) | `text`, `barged_in?`, `language?` (see §7.4) | `user_speak*.json` |
| `dtmf_received` | [/api/events/dtmf-received](https://flow.sipgate.io/api/events/dtmf-received) | `digit` (`0`-`9`, `*`, `#`) | `dtmf_received.json` |
| `assistant_speak` | [/api/events/assistant-speak](https://flow.sipgate.io/api/events/assistant-speak) | `text?`, `ssml?`, `duration_ms?`, `speech_started_at?` | `assistant_speak.json` |
| `assistant_speech_ended` | [/api/events/assistant-speech-ended](https://flow.sipgate.io/api/events/assistant-speech-ended) | `session` only | `assistant_speech_ended.json` |
| `user_input_timeout` | [/api/events/user-input-timeout](https://flow.sipgate.io/api/events/user-input-timeout) | `session` only | `user_input_timeout.json` |
| `session_end` | [/api/events/session-end](https://flow.sipgate.io/api/events/session-end) | `session` only; **no action may be returned** | `session_end.json` |
| `sms_failed` | [/api/events#sms-failed](https://flow.sipgate.io/api/events#sms-failed) | `recipient`, `reason`, `message?` | `sms_failed.json` |
| `error` | [/api/events/error](https://flow.sipgate.io/api/events/error) | `code`, `severity`, `message`, `action_type?` | `error.json` |

Enumerations, all verified on the same pages and all carried permissively with
an `Other(String)` escape hatch:

* `transfer_failed_reason`: `busy`, `rejected`, `no_answer`, `number_not_found`,
  `technical_error`, `unknown`.
* `sms_failed.reason`: `sender_not_allowed`, `insufficient_balance`,
  `no_sms_extension`, `smsc_unavailable`, `unknown`.
* `error.code`: `action_invalid`, `action_unknown_session`,
  `transcription_unavailable`, `transcription_switch_failed`,
  `synthesis_unavailable`, `transfer_target_invalid`, `internal_error` — the page
  says explicitly that new codes may appear, so unknown codes stay unknown strings.
* `error.severity`: `warning`, `error`.
* `session.direction`: `inbound`, `outbound`.

Which events accept an action response is taken from the "Response Requirements"
table on <https://flow.sipgate.io/api/events>: every event except `session_end`,
`user_speech_started` and `sms_failed` (the last two are not in the table at all,
so `Event::accepts_actions` reports `false` and the handler answers `204`).

## 2. Flow actions — verified

Source: <https://flow.sipgate.io/api/actions> (summary) plus one page per action.
The wire shape is flat: `type`, `session_id`, then the action's own fields.

| `type` | Source page | Fields modelled |
| --- | --- | --- |
| `speak` | [/api/actions/speak](https://flow.sipgate.io/api/actions/speak) | `text` XOR `ssml`, `tts{provider,language,voice}`, `barge_in{strategy,minimum_characters,allow_after_ms}`, `user_input_timeout_seconds`, `vad{end_of_turn_silence_ms}` |
| `audio` | [/api/actions/audio](https://flow.sipgate.io/api/actions/audio) | `audio` (base64 WAV, 16 kHz mono 16-bit PCM), `barge_in` |
| `mix_audio` | [/api/actions/mix-audio](https://flow.sipgate.io/api/actions/mix-audio) | `audio` (unless `stop`), `volume` 0.0–1.0 (default 0.5), `stop` |
| `hangup` | [/api/actions/hangup](https://flow.sipgate.io/api/actions/hangup) | — |
| `transfer` | [/api/actions/transfer](https://flow.sipgate.io/api/actions/transfer) | `target_phone_number`, `caller_id_name?`, `caller_id_number?`, `timeout` 5–120 |
| `barge_in` | [/api/actions/barge-in](https://flow.sipgate.io/api/actions/barge-in) | — (stops current playback) |
| `configure_transcription` | [/api/actions/configure-transcription](https://flow.sipgate.io/api/actions/configure-transcription) | `provider?`, `languages?` (1–4 BCP-47), `custom_vocabulary?` (≤100 entries, ≤200 chars), `vad?` |
| `send_sms` | [/api/actions/send-sms](https://flow.sipgate.io/api/actions/send-sms) | `phone_number` (E.164 digits, `+` stripped), `message` |

Verified details that the code enforces:

* `speak` requires **either** `text` **or** `ssml`, not both ("Either `text` OR
  `ssml` is required").
* `transfer.timeout` is an integer **5–120**; setting it is what enables the
  returning `session_start` with `transfer_failed_reason`.
* `barge_in.minimum_characters` is **1–100** (default 3).
* `configure_transcription` is a no-op when no field is set ("sending none of
  them is a no-op") — the builder refuses to send that.
* `custom_vocabulary`: max 100 entries, max 200 characters per entry.
* `transfer` numbers: "E.164 format without leading + (recommended)".
* Flow audio: WAV, 16 kHz, mono, 16-bit PCM, base64.
* `mix_audio.volume`: `0.0`–`1.0`, default `0.5`.
* `barge_in` has four documented strategies: `none`, `manual`,
  `minimum_characters`, `immediate`; `immediate` is missing from the SDK's
  TypeScript union, but documented on the page — see §7.5.

## 3. Webhook / response contract — verified

Sources: <https://flow.sipgate.io/api/http-webhooks>,
<https://flow.sipgate.io/api/authentication>,
<https://flow.sipgate.io/api/actions#response-format>.

* Events arrive as `POST` with `Content-Type: application/json`.
* Authentication is a **shared secret** the dashboard stores and Flow sends in a
  header: `X-API-TOKEN` (authentication page). The webhooks page's request
  example instead shows `X-API-Key` — see §7.2.
* A handler answers `200` with one action object or an array (executed in
  order), or `204 No Content`. `200` with `{}` or `[]` means the same as `204`.
* Response statuses: `200` action returned, `204` no action, `400` invalid
  request, `401` unauthorized, `500` server error.
* `session_end` accepts **no** action.
* The webhook timeout is "approximately 5 seconds"
  (<https://flow.sipgate.io/api/guides/async-hold-pattern>), which is why
  `FlowResponse::none()` exists.

## 4. Outbound Flow calls — verified path, composed URL

Source: <https://flow.sipgate.io/api/guides/outbound-calls>.

```http
POST /v3/ai-flows/:aiFlowId/call
Authorization: Bearer ***
Content-Type: application/json

{ "billingDevice": "e2", "toPhoneNumber": "+4915…" }
```

* `201 Created` on success; `400` when the Flow has no `phone_number`; `404`
  when the Flow does not exist.
* `billingDevice` is the billing device suffix issued during onboarding
  (`"e2"`); `toPhoneNumber` is full E.164, the leading `+` optional because the
  service adds it.
* The resulting session carries `"direction": "outbound"`.
* The host is not printed in that page; the official SDK defaults `baseUrl` to
  `https://api.sipgate.com` (<https://flow.sipgate.io/sdk/api-reference>), so
  `FlowClient` uses that base. See §7.1 for the caveat.
* Access is granted per account by sipgate support; expect `403`/`404` without it.

## 5. REST API v2 — verified against the public Swagger

Source: <https://api.sipgate.com/v2/swagger.json> (`host` `api.sipgate.com`,
`basePath` `/v2`), rendered at <https://api.sipgate.com/v2/doc>.

| Method | Path | `operationId` | Request type | Success | Implemented as |
| --- | --- | --- | --- | --- | --- |
| POST | `/sessions/sms` | `sendWebSms` | `SendWebSmsRequest` | 204 | `RestClient::send_sms` |
| POST | `/sessions/fax` | `sendFax` | `SendFaxRequest` | 200 → `SendFaxSessionResponse` | `send_fax` |
| POST | `/sessions/fax/resend` | `resendFax` | `ResendFaxRequest` | 200 | `resend_fax` |
| POST | `/sessions/calls` | `newCall` | `NewCallRequest` | 200 → `InitiateNewCallSessionResponse` | `new_call` |
| POST | `/sessions/ivr/recording` | `newIvrRecording` | `NewIvrRecordingRequest` | 200 | `record_ivr` |
| POST | `/sessions/voicemail/recording` | `newRecording` | `NewVoicemailRecordingRecordingRequest` | 200 | `record_voicemail` |
| POST | `/sessions/voicemail/play` | `playRecording` | `PlayRecordingRequest` | 200 | `play_voicemail` |
| GET | `/calls` | `getCalls` | — | 200 → `Calls` | `calls` |
| POST | `/calls` | `createCall` | inline object | 200 → `CreateCallResponse` | `channel_call` |
| DELETE | `/calls/{callId}` | `hangupCall` | — | 204 | `hangup` |
| POST | `/calls/{callId}/dtmf` | `sendCallDtmf` | `DtmfRequest` | 204 | `send_dtmf` |
| POST | `/calls/{callId}/announcements` | `startCallAnnouncement` | `AnnouncementRequest` | 204 | `announce` |
| PUT | `/calls/{callId}/recording` | `setCallRecording` | `RecordingRequest` | 204 | `set_recording` |
| PUT | `/calls/{callId}/hold` | `setCallHold` | `BooleanRequest` | 204 | `set_hold` |
| PUT | `/calls/{callId}/muted` | `setCallMuted` | `BooleanRequest` | 204 | `set_muted` |
| POST | `/calls/{callId}/transfer` | `transferCall` | `TransferRequest` | 204 | `transfer` |

Bodies (all from the Swagger `definitions`, rendered as fixtures under
`tests/fixtures/rest/`):

* `SendWebSmsRequest` — required `smsId`, `recipient`, `message`; optional
  `sendAt` (int64). Example recipient `+491…`.
* `SendFaxRequest` — required `base64Content` (**maxLength 28 330 000**),
  `faxlineId`, `filename`, `recipient`.
* `ResendFaxRequest` — required `faxId`; optional `faxlineId`.
* `NewCallRequest` — required `callee`, `caller`; optional `callerId`,
  `deviceId` ("only required if the caller parameter is a phone number").
* `DtmfRequest` — required `sequence`.
* `AnnouncementRequest` — required `url`; "mono 16bit PCM WAV … 8kHz", not
  available on Neo PBX accounts.
* `RecordingRequest` — required `value`; optional `announcement` (default true).
* `BooleanRequest` — required `value`.
* `TransferRequest` — required `attended`, `phoneNumber`; optional `callerId`.
* `PlayRecordingRequest` — `datadId`, `deviceId` (both optional in the schema;
  `datadId` is spelled that way — see §7.6).
* `NewIvrRecordingRequest` / `NewVoicemailRecordingRecordingRequest` —
  `deviceId`, `endpoint`, `targetId`, all optional.
* `Call` / `Participant` — `callId`, `hold`, `muted`, `recording`,
  `participants[]`; participant `participantId`, `phoneNumber` (may be the
  literal `<unknown>`), `hold`, `muted`, `owner`.

Documented error statuses: 400 (invalid request), 402 (insufficient funds), 403
(not allowed), 404 (unknown call/flow), 409 (call not yet established for hold
and transfer), 500. `Retry-After` is not mentioned by sipgate; the client
honours it when present because it is standard HTTP.

## 6. Authentication — verified, with one inference

**Flow webhooks** use the shared secret of §3. There is no OAuth2 on the inbound
side.

**REST API v2** accepts a Personal Access Token as `Authorization: Basic
base64(tokenId:token)` (<https://en.sipgate.io/rest-api/authentication>), or an
OAuth2 access token as `Authorization: Bearer …`. In this crate a PAT is
`StaticToken` (sent as a bearer, which sipgate also accepts for API clients) and
OAuth2 is `OAuth2Client`.

**OAuth2 endpoints and capabilities** — verified from the realm's discovery
document
<https://login.sipgate.com/auth/realms/third-party/.well-known/openid-configuration>:

* `token_endpoint` = `https://login.sipgate.com/auth/realms/third-party/protocol/openid-connect/token`
  (identical to the URL in the REST authentication page).
* `grant_types_supported` includes **`client_credentials`**.
* `token_endpoint_auth_methods_supported` includes `client_secret_basic` and
  `client_secret_post`.
* Token responses carry `access_token`, `token_type: "bearer"`, `expires_in:
  300`, `refresh_token`, `session_state`, `not-before-policy` (documented
  example).

The REST authentication page's own examples post **form-encoded**
`client_id`/`client_secret` (i.e. `client_secret_post`), so that is what
`ClientCredentials::token_request_body` does. The page documents the
authorization-code grant and the refresh-token grant; it does not spell out the
client-credentials request, which is why the grant is quoted from the discovery
document rather than the prose.

Refresh margin: tokens live 300 s; the client treats a token as stale 60 s
before expiry (configurable), and re-fetches on 401 once.

---

## Unverified

These are the shapes I could not confirm from a public source. Each is either
omitted or handled in the tolerant direction, never assumed correct.

### 7.1 Full outbound-call URL
The path `/v3/ai-flows/:aiFlowId/call` is documented, but no full URL is printed
and the Swagger document only covers `/v2`. `FlowClient` composes it from the
SDK's documented default base (`https://api.sipgate.com`). A wrong host would
surface as a 404, which is why `with_base_url` exists.

### 7.2 `X-API-TOKEN` vs `X-API-Key`
The authentication page names the header `X-API-TOKEN`; the webhooks page's
request example shows `X-API-Key`. Both constants are exported; the verifier
only compares the value, so a handler can read whichever header its framework
exposes. Which one Flow actually sends in production is **unverified**.

### 7.3 Action delivery outside the webhook
The barge-in and `configure_transcription` pages mention "external API POST" as
a third channel besides the webhook response and the WebSocket, but no path,
method, auth scheme or body envelope is published. **No client method is
implemented for it.** (The 0.1 stub guessed `POST {base}/calls/{id}/actions`;
nothing in either API's documentation matches that path.)

### 7.4 `user_speak.language`
The field table for `user_speak` lists only `type`, `text`, `barged_in` and the
session fields, but the `configure_transcription` page's JavaScript example reads
`event.language` as a BCP-47 code. The field is modelled as optional and is
**unverified**; nothing in the crate depends on it being present.

### 7.5 `barge_in.strategy: "immediate"`
Documented on <https://flow.sipgate.io/api/barge-in> with latency figures, but
absent from the `AiFlowActionSpeak.barge_in.strategy` union in
<https://flow.sipgate.io/sdk/advanced/actions>. Modelled because the API page is
the protocol description; the SDK type may simply lag.

### 7.6 `datadId`
`PlayRecordingRequest` spells the voicemail identifier `datadId`. Almost
certainly a typo for `dataId` in the published schema, but the wire key is what
the service documents, so that is what is sent. Verify against a sandbox before
relying on voicemail playback.

### 7.7 `transfer` required fields and the `transfer_to` spelling
The field table marks `caller_id_name` and `caller_id_number` as **required**,
while the `dtmf_received` example sends a transfer as
`{"type":"transfer","session_id":"…","transfer_to":"49211100200"}` — no caller id
and a different field name. The model follows the field table
(`target_phone_number`) and treats the caller-id pair as optional and omitted
when unset, so both documented shapes can be produced. `transfer_to` is **not**
emitted, because the field table does not mention it.

### 7.8 Client-credentials tokens against user-scoped endpoints
The realm advertises `client_credentials`, but every prose example uses the
authorization-code grant or a PAT, and a client-credentials token represents the
OAuth client rather than a user. Whether `api.sipgate.com/v2` accepts one for
user-scoped endpoints (`sessions:*`, `rtcm:*`) is **unverified** — test it
against an account before choosing this grant in production. Personal access
tokens are the documented path.

### 7.9 Rate limits and `Retry-After` on the REST API
No public page states a rate limit, a burst budget or a `Retry-After` policy for
`api.sipgate.com`. The client retries 429/5xx with bounded backoff and honours
`Retry-After` if a proxy sends it, but the numbers are this crate's defaults,
not sipgate's.

### 7.10 Flow fax / voicemail / recording / DTMF actions
The issue that drove this work listed them as Flow actions. They do not exist in
the Flow action catalogue (`speak`, `audio`, `mix_audio`, `hangup`, `transfer`,
`barge_in`, `configure_transcription`, `send_sms`). The equivalents live in REST
v2 (`/sessions/fax`, `/sessions/voicemail/*`, `/calls/{id}/dtmf`,
`/calls/{id}/recording`) and are implemented there.

## 8. Deliberately not modelled

* **Push API (classic)** — <https://en.sipgate.io/push-api/api-references>:
  `event=newCall` as `application/x-www-form-urlencoded`, answered with **XML**
  (`<Dial>`, `<Play>`, `<Gather>`, `<Reject>`), follow-up events `onAnswer`,
  `onHangup`, `onData`. A different protocol (form + XML, no JSON), so it would
  be a different crate. `WebhookVerifier` rejects it explicitly with
  `Error::UnsupportedContentType` rather than half-parsing it.
* **WebSocket transport** — documented at
  <https://flow.sipgate.io/api/websocket>: Flow *connects to you*, so a client
  would need a server framework. The event and action types are transport
  agnostic and work there as-is.
* **The remaining REST v2 surface** (accounts, devices, contacts, history,
  phonelines, numbers, templates, …) — out of scope for a flow/telephony client;
  it is account administration, not call handling.
* **TTS voice catalogues** (`/api/tts-providers`) — data, not protocol; pass any
  documented voice id through `Tts`.

## 9. Fixture provenance

| Fixture | Source |
| --- | --- |
| `flow/session_start.json` | <https://flow.sipgate.io/api/events/session-start> (Event Structure) |
| `flow/session_start_transfer_failed.json` | same page (Returning Callers) |
| `flow/user_speech_started.json` | <https://flow.sipgate.io/api/events/user-speech-started> |
| `flow/user_speak.json`, `flow/user_speak_barged_in.json` | <https://flow.sipgate.io/api/events/user-speak> |
| `flow/dtmf_received.json` | <https://flow.sipgate.io/api/events/dtmf-received> |
| `flow/assistant_speak.json` | <https://flow.sipgate.io/api/events/assistant-speak> |
| `flow/assistant_speech_ended.json` | <https://flow.sipgate.io/api/events/assistant-speech-ended> |
| `flow/user_input_timeout.json` | <https://flow.sipgate.io/api/events/user-input-timeout> |
| `flow/session_end.json` | <https://flow.sipgate.io/api/events/session-end> |
| `flow/sms_failed.json` | <https://flow.sipgate.io/api/events#sms-failed> |
| `flow/error.json` | <https://flow.sipgate.io/api/events/error> |
| `flow/unknown_event.json` | synthetic, for the permissive path |
| `rest/*_request.json` | `definitions` examples in <https://api.sipgate.com/v2/swagger.json> |
| `rest/calls_response.json` | `Call` / `Participant` definitions, same document |
