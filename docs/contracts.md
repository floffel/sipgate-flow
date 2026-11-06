# Verified contracts

Every shape this crate accepts or sends, with the public document it came from.
Retrieved **2026-10-24**, in two passes: the first covered the published pages
and the v2 Swagger, the second the machine-readable v3 documents and sipgate's
published clients (§9 lists every source and how it was fetched). A third pass on
**2026-11-05** covered the classic Push API (§11, §7.10).

Rule for this document: a shape is **verified** only when a public sipgate
artifact states it — a documentation page, the v2 Swagger, the **v3 OpenAPI
document**, the realm's discovery document, or sipgate's own published code
(the official TypeScript SDK on npm, the `sipgateio` client, the official n8n
node). Anything I could not confirm is listed under [Unverified](#7-unverified),
and the code treats it accordingly — never as if it were a fact.

For the 0.1.0 release gate, verification is **documentation-level only**. No
live sipgate sandbox or account-backed contract pass was performed; every
positive claim below rests on the cited public source. The only gaps that truly
need account access are tracked in §7.4 (`datadId` on
`POST /sessions/voicemail/play`) and §7.5 (client-credentials tokens against
user-scoped endpoints). No additional live-only gaps are invented here.

---

## 0. Three products, all three of which this crate speaks

| Product | Protocol | Auth | In this crate |
| --- | --- | --- | --- |
| **sipgate flow** (`flow.sipgate.io`) | JSON both ways; actions go in the **webhook response** | shared secret in `X-API-TOKEN` | `flow::*` |
| **sipgate REST API v2** (`api.sipgate.com/v2`) | JSON in/out over REST | OAuth2 bearer / PAT (Basic) | `rest::*` |
| **sipgate.io Push API** (classic) | `application/x-www-form-urlencoded` in, **XML** out | none documented (§7.10) | `push::*` |

The 0.1 stub conflated them: it parsed `{"event":"answered","callId":…}`
(shaped after the Push API), emitted `{"action":"tts"}` (a name none of the
products uses), and posted to `{base}/calls/{id}/actions` — a path that exists
in **none** of them. All three assumptions are gone.

---

## 1. Flow events — verified

Source: <https://flow.sipgate.io/api/events> (event table) plus one page per
event. Every event carries `type` and `session`; `session.id` is the value an
action must echo back as `session_id`.

| `type` | Source page | Fields modelled | Fixture |
| --- | --- | --- | --- |
| `session_start` | [/api/events/session-start](https://flow.sipgate.io/api/events/session-start) | `session.{id,account_id,phone_number,direction,from_phone_number,to_phone_number}`, `transfer_failed_reason?` | `tests/fixtures/flow/session_start*.json` |
| `user_speech_started` | [/api/events/user-speech-started](https://flow.sipgate.io/api/events/user-speech-started) | `session` only; WebSocket-only event | `user_speech_started.json` |
| `user_speak` | [/api/events/user-speak](https://flow.sipgate.io/api/events/user-speak) | `text`, `barged_in?`, `language?` (see §7.2) | `user_speak*.json` |
| `user_barge_in` | **official SDK only**, see below | `text` | `user_barge_in.json` |
| `dtmf_received` | [/api/events/dtmf-received](https://flow.sipgate.io/api/events/dtmf-received) | `digit` (`0`-`9`, `*`, `#`) | `dtmf_received.json` |
| `assistant_speak` | [/api/events/assistant-speak](https://flow.sipgate.io/api/events/assistant-speak) | `text?`, `ssml?`, `duration_ms?`, `speech_started_at?` | `assistant_speak.json` |
| `assistant_speech_ended` | [/api/events/assistant-speech-ended](https://flow.sipgate.io/api/events/assistant-speech-ended) | `session` only | `assistant_speech_ended.json` |
| `user_input_timeout` | [/api/events/user-input-timeout](https://flow.sipgate.io/api/events/user-input-timeout) | `session` only | `user_input_timeout.json` |
| `session_end` | [/api/events/session-end](https://flow.sipgate.io/api/events/session-end) | `session` only; **no action may be returned** | `session_end.json` |
| `sms_failed` | [/api/events#sms-failed](https://flow.sipgate.io/api/events#sms-failed) | `recipient`, `reason`, `message?` | `sms_failed.json` |
| `error` | [/api/events/error](https://flow.sipgate.io/api/events/error) | `code`, `severity`, `message`, `action_type?` | `error.json` |

`user_barge_in` is not in the documentation's event table, but the official SDK
declares it twice — `AiFlowEventType.USER_BARGE_IN = "user_barge_in"` and
`AiFlowEventUserBargeInSchema` (`{session, type, text}`, `text` required) in
`@sipgate/ai-flow-sdk` 2.1.0 — and ships a dedicated `onUserBargeIn` handler.
`text` is modelled as a `String` that defaults to empty, and
`Event::accepts_actions` answers `false` for it: the documentation's "Response
Requirements" table does not cover the event, and the conservative answer for an
event with an unknown response contract is `204`.

Enumerations, all verified on the pages listed above (and, for the strategies
and providers, in the SDK's enums as well) and all carried permissively with an
`Other(String)` escape hatch:

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

Source: <https://flow.sipgate.io/api/actions> (summary) plus one page per action,
cross-checked against `AiFlowActionSchema` in `@sipgate/ai-flow-sdk` 2.1.0,
which is the same union: `speak`, `audio`, `hangup`, `barge_in`, `transfer`,
`configure_transcription`, `send_sms`, `mix_audio` — eight, no more. The wire
shape is flat: `type`, `session_id`, then the action's own fields.

| `type` | Source page | Fields modelled |
| --- | --- | --- |
| `speak` | [/api/actions/speak](https://flow.sipgate.io/api/actions/speak) | `text` XOR `ssml`, `tts{provider,language,voice,speed}`, `barge_in{strategy,minimum_characters,allow_after_ms}`, `user_input_timeout_seconds`, `vad{end_of_turn_silence_ms}` |
| `audio` | [/api/actions/audio](https://flow.sipgate.io/api/actions/audio) | `audio` (base64 WAV, 16 kHz mono 16-bit PCM), `barge_in` |
| `mix_audio` | [/api/actions/mix-audio](https://flow.sipgate.io/api/actions/mix-audio) | `audio` (unless `stop`), `volume` 0.0–1.0 (default 0.5), `stop` |
| `hangup` | [/api/actions/hangup](https://flow.sipgate.io/api/actions/hangup) | — |
| `transfer` | [/api/actions/transfer](https://flow.sipgate.io/api/actions/transfer) | `target_phone_number`, `caller_id_name?`, `caller_id_number?`, `timeout` 5–120 |
| `barge_in` | [/api/actions/barge-in](https://flow.sipgate.io/api/actions/barge-in) | — (stops current playback) |
| `configure_transcription` | [/api/actions/configure-transcription](https://flow.sipgate.io/api/actions/configure-transcription) | `provider?`, `languages?` (1–4 BCP-47), `custom_vocabulary?` (≤100 entries, ≤200 chars), `vad?` |
| `send_sms` | [/api/actions/send-sms](https://flow.sipgate.io/api/actions/send-sms) | `phone_number` (E.164 digits, `+` stripped), `message` |

TTS providers — all four the SDK's `TtsConfigSchema` discriminates on, three of
them on <https://flow.sipgate.io/api/tts-providers>:

| `provider` | Fields | Documented where |
| --- | --- | --- |
| `kugelaudio` | `voice` (e.g. `963`), `language` (e.g. `de`), `speed` | TTS page + SDK (`speed` is SDK-only) |
| `azure` | `language` (BCP-47), `voice` | TTS page + SDK |
| `eleven_labs` | `voice` (provider id) | TTS page + SDK |
| `openai` | `voice` (`alloy`, `echo`, `fable`, `onyx`, `nova`, `shimmer`, `coral`, `sage`) | **SDK only** |

Verified details that the code enforces:

* `speak` requires **either** `text` **or** `ssml`, not both ("Either `text` OR
  `ssml` is required"). The SDK's schema leaves both optional, so this is the
  page's rule and the crate's builder enforces it.
* `transfer.timeout` is an integer **5–120**; setting it is what enables the
  returning `session_start` with `transfer_failed_reason`.
* `barge_in.minimum_characters` is **1–100** (default 3).
* `configure_transcription` is a no-op when no field is set ("sending none of
  them is a no-op") — the builder refuses to send that.
* `custom_vocabulary`: max 100 entries, max 200 characters per entry.
* `transfer` numbers: "E.164 format without leading + (recommended)".
* Flow audio: WAV, 16 kHz, mono, 16-bit PCM, base64.
* `mix_audio.volume`: `0.0`–`1.0`, default `0.5`.
* `barge_in` has exactly four strategies, `none`, `manual`, `minimum_characters`,
  `immediate`, in the page **and** in `BargeInStrategy` in SDK 2.1.0 (`IMMEDIATE =
  "immediate"`, "Barge in immediately when first word is detected"). Earlier SDK
  versions omitted the variant; 2.1.0 has it, so the modelling question is closed.

## 3. Webhook / response contract — verified

Sources: <https://flow.sipgate.io/api/http-webhooks>,
<https://flow.sipgate.io/api/authentication>,
<https://flow.sipgate.io/api/actions#response-format>.

* Events arrive as `POST` with `Content-Type: application/json`.
* Authentication is a **shared secret** the dashboard stores and Flow sends in
  the `X-API-TOKEN` header — see §3.1.
* A handler answers `200` with one action object or an array (executed in
  order), or `204 No Content`. `200` with `{}` or `[]` means the same as `204`.
* Response statuses: `200` action returned, `204` no action, `400` invalid
  request, `401` unauthorized, `500` server error.
* `session_end` accepts **no** action.
* The webhook timeout is "approximately 5 seconds"
  (<https://flow.sipgate.io/api/guides/async-hold-pattern>), which is why
  `FlowResponse::none()` exists.

### 3.1 The header is `X-API-TOKEN`

Settled in the second pass. Three independent first-party statements:

1. The authentication page's normative **"Request Headers"** section: "The Flow
   service sends the following headers: `X-API-TOKEN` — The shared secret you
   configured in your webhook settings; `Content-Type: application/json`;
   `User-Agent`." Its three code samples (Python, Node, Go) all read
   `X-API-TOKEN`.
2. sipgate's own webhook consumer, the **`@sipgate/n8n-nodes-ai-flow`** node
   (author `sipgate GmbH`, repository `github.com/sipgate/n8n-nodes-ai-flow`),
   ships `X-API-TOKEN` as the *default* `headerName` of its Flow trigger and its
   tests verify against `x-api-token`.
3. `X-API-Key` appears exactly twice in the whole corpus: once in the request
   example on the webhooks page (`X-API-Key: … (optional)`), and once in a
   hand-written Express middleware sample on `/sdk/integrations/express` that the
   *reader* writes, not the service. No first-party code reads it.

Both names remain exported (`SECRET_HEADER`, `SECRET_HEADER_LEGACY`) and
`WebhookVerifier::verify` compares the value, not the name, so a framework that
normalises headers differently still works.

### 3.2 The WebSocket channel — verified

Source: <https://flow.sipgate.io/api/websocket> (and the same page as
<https://flow.sipgate.io/api/websocket.md>, which the docs site offers for LLMs).

* **Who connects**: "When a phone call starts, the Flow Service initiates a
  WebSocket connection to your application." Flow is the client; the
  application runs the server, and the URL is configured in the Flow dashboard
  (`wss://your-domain.com/ai-flow/websocket`, `ws://localhost:8080/websocket`
  for local development).
* **Framing**: "Events are sent as JSON strings" — one event per message, the
  same shape as the webhook body (the page's example is the
  `user_speak` payload). Actions are sent back the same way; the page's example
  is one flat object with `type`, `session_id` and the action's own fields.
  `@sipgate/ai-flow-sdk` 2.1.0's `ws(ws)` handler does
  `ws.send(JSON.stringify(actions))`, where `actions` is the handler's return
  value — a single action object or an array — so a response with several
  actions travels as one array message, which is why the crate reuses
  `FlowResponse` unchanged.
* **Addressing**: an action names its session with `session_id`, not with the
  connection. The page describes "proactive event delivery" and "unsolicited
  actions", so one connection is not one session from the protocol's point of
  view; the crate treats one connection as one call because that is the
  documented lifecycle ("When a call starts, it connects to your server. When
  the call ends, it may close the connection").
* **Heartbeat**: "The Flow Service may send ping frames to keep the connection
  alive. Your server should respond with pong frames."
* **Event coverage**: the event table marks every event `HTTP + WebSocket` except
  `user_speech_started`, which is `WebSocket only` — hence the typed event set is
  the same one §1 describes.
* **Response contract**: the page names no status codes and no error envelope on
  this transport. An action that arrives for an event with no action contract
  (or none at all) has no documented acknowledgement, so the crate refuses to
  write it locally (`Error::ActionNotAccepted`) instead of relying on the
  service to discard it.

### 3.3 What the channel does not document

See §7.9: the handshake carries no documented authentication.

## 4. Outbound Flow calls — verified end to end

Sources: <https://api.sipgate.com/v3/openapi.json> (the machine-readable v3
document, 402 paths) and `@sipgate/ai-flow-sdk` 2.1.0 (`dist/index.js`).

```http
POST https://api.sipgate.com/v3/ai-flows/:aiFlowId/call
Authorization: Bearer <token>
Content-Type: application/json

{ "billingDevice": "e2", "toPhoneNumber": "+4915…" }
```

| Evidence | What it pins down |
| --- | --- |
| `servers[0].url = "https://api.sipgate.com/v3"` + path `/ai-flows/{aiFlowId}/call` | the **full URL**, including the host the guide does not print |
| `operationId: initiateOutboundCall`, tag `AiFlows` | the operation exists in v3, not v2 |
| requestBody `InitiateOutboundCallDto`: `billingDevice` (required, "Billing device suffix (e.g. 'e2'). masterSipId is prepended automatically"), `toPhoneNumber` (required, "full E.164 … leading '+' is optional and is added automatically when missing") | the exact body and its two required fields |
| `201` → `InitiateOutboundCallResponseDto`, `callSid` required ("PBXCore call identifier", e.g. `pbx-c-ffffffff-abba-acdc-acab-ffffffffffff`) | the response body this crate types as `OutboundCallReceipt` |
| `400` "Client has no phone_number configured", `401`/`403` ("The calling user is not an admin"), `404` "Flow not found", `500` | status classification |
| `security: [{"bearer": []}, {"oauth2": ["all", "ai:flows:write"]}]` | both a bearer credential and an OAuth2 token with `ai:flows:write` are accepted |
| SDK: `DEFAULT_BASE_URL = "https://api.sipgate.com"`, `` `${baseUrl}/v3/ai-flows/${aiFlowId}/call` ``, `Authorization: Bearer`, body `{billingDevice, toPhoneNumber}` | the same URL and header, from running code |
| guide: "Only available upon request and after a positive review by sipgate support" | why a fresh account sees 403/404 |

The resulting session carries `"direction": "outbound"` (guide, §"Outbound Call
Flow"). `FlowClient` composes the base URL from the v3 `servers` entry and keeps
`try_with_base_url` for a proxy or a regional host; `with_base_url_for_local_testing`
is the explicit opt-in for plaintext local test doubles.

### 4.1 In-product v3 webhook and TTS voices — verified

The same v3 `OpenAPI` document contains the first two in-product surfaces beyond
the outbound call. They are implemented by `FlowClient`; both use the v3 server
URL and the same bearer credential as §4.

| Method | Path | `operationId` | Request type | Success | Implemented as |
| --- | --- | --- | --- | --- | --- |
| PUT | `/ai-webhooks` | `updateWebhookSettings` | `WebhookSettingsUpdateRequest` | 200/201 | `FlowClient::update_ai_webhook` |
| GET | `/ai-webhooks` | `getWebhookSettings` | — | 200 → `WebhookSettingsResponse` | `FlowClient::ai_webhook` |
| DELETE | `/ai-webhooks` | `deleteWebhookSettings` | — | 204 | `FlowClient::delete_ai_webhook` |
| GET | `/webhooks` | `getWebhookConfigs` | — | 200 → `[WebhookConfigResponse]` | `FlowClient::ai_webhook_configs` |
| POST | `/webhooks` | `createWebhookConfig` | `WebhookConfigRequest` | 201 → `WebhookConfigResponse` | `FlowClient::create_ai_webhook_config` |
| PUT | `/webhooks/{configId}` | `replaceWebhookConfig` | `WebhookConfigRequest` | 200 → `WebhookConfigResponse` | `FlowClient::replace_ai_webhook_config` |
| DELETE | `/webhooks/{configId}` | `deleteWebhookConfig` | — | 204 | `FlowClient::delete_ai_webhook_config` |
| POST | `/webhooks/{configId}/headers` | `addWebhookConfigHeader` | `WebhookHeaderDto` | 201 → `WebhookHeaderDto` | `FlowClient::add_ai_webhook_header` |
| DELETE | `/webhooks/{configId}/headers/{headerName}` | `deleteWebhookConfigHeader` | — | 204 | `FlowClient::delete_ai_webhook_header` |
| GET | `/tts/voices` | `listVoices` | — | 200 → `GenericListResponseTtsVoice` | `FlowClient::tts_voices` |

* `WebhookSettingsUpdateRequest` and `WebhookSettingsResponse` both carry one
  `webhookUrl` string. The schema publishes no secret field, so the URL is the
  whole contract; the client validates it as an absolute `https://` URL before
  the request exists.
* `GenericListResponseTtsVoice` is `{"items": [voiceId, ...]}` in the current
  document. The adjacent frontdesk catalogue uses richer `VoiceResponse`
  objects (`voiceId`, `name`, `languages`, `previewUrl`, `recommended`,
  `beta`), so `TtsVoice` accepts both shapes and preserves unknown fields in
  `raw()`.
* The current AI webhook config surface is the `WebhookConfigRequest` /
  `WebhookConfigResponse` pair: `{active, entityIds, name, urls}`, with the
  response adding `webhookId` and `headers`. `AiWebhookConfig` validates the
  `https://` target URLs, name length and non-empty entity ids before the wire,
  and `AiWebhookHeader` enforces the documented `X-` prefix, rejects `#`/CR/LF
  and redacts the value in `Debug`.

### 4.2 In-product v3 account administration writes — verified

Source: <https://api.sipgate.com/v3/swagger.json> (Swagger 2.0). The faxline
creation and member writes are also present in
<https://api.sipgate.com/v3/openapi.json> under `createFaxExtension`,
`addFaxMembers` and `removeFaxMembers`. All operations below are represented by
[`V3AdminOperation`] and executed through `FlowClient::execute_v3_admin`; the
few read/status and convenience operations named in the last column have direct
methods as well.

| Method | Path | `operationId` | Request type | Implemented as |
| --- | --- | --- | --- | --- |
| GET | `/account/cancellation` | `getAccountCancellation` | — | `v3_account_cancellation` |
| POST | `/account/cancellation` | `createAccountCancellation` | `AccountCancellationRequest` | `request_v3_account_cancellation` |
| DELETE | `/account/cancellation` | `deleteAccountCancellation` | — | `revoke_v3_account_cancellation` |
| GET | `/account/event-lifetime` | `getEventLifetime` | — | `v3_event_lifetime` |
| PUT | `/account/event-lifetime` | `setEventLifetime` | `EventLifetimeRequest` | `set_v3_event_lifetime` |
| POST | `/devices/mobile` | `createMobileDevice` | `CreateMobileDeviceRequest` | `CreateMobileDevice` |
| POST | `/devices/register` | `createRegisterDevice` | `CreateRegisterDeviceRequest` | `CreateRegisterDevice` |
| PUT | `/devices/{deviceId}/alias` | `changeDeviceAlias` | `SetDeviceAliasRequest` | `SetDeviceAlias` |
| PUT | `/devices/{deviceId}/fancyCodec` | `changeFancyCodec` | `SetFancyCodecRequest` | `SetFancyCodec` |
| PUT | `/devices/{deviceId}/pending-sim` | `setPendingSim` | `SetPendingSimRequest` | `SetPendingSim` |
| POST | `/devices/{deviceId}/sim` | `activateSim` | `ActivateSimRequest` | `ActivateSim` |
| PUT | `/devices/{deviceId}/sim/{id}` | `updateSim` | `ActivateSimRequest` | `UpdateSim` |
| PUT | `/devices/{deviceId}/sim/{simId}/intendedUse` | `setIntendedUse` | `SetIntendedUseRequest` | `SetSimIntendedUse` |
| PUT | `/devices/{deviceId}/smsSim` | `setSmsSim` | `SetSmsReceivingSimRequest` | `SetSmsSim` |
| POST | `/devices/{deviceId}/contracts` | `createContract_1` | `CreateDeviceContractRequest` | `CreateDeviceContract` |
| POST | `/devices/{deviceId}/contracts/{contractId}/cancellation` | `cancelContract_1` | `CancelDeviceContractRequest` | `CancelDeviceContract` |
| DELETE | `/devices/{deviceId}/contracts/{contractId}/cancellation` | `rollbackCancellation_1` | — | `RevokeDeviceContractCancellation` |
| PUT | `/phone-numbers/mobile/opt-in` | `releaseMobileNumbersForExport` | `ReleaseMobileNumbersForExportRequest` | `ReleaseMobileNumbers` |
| PUT | `/routings` | `createNumberRouting` | `CreateRoutingRequest` | `CreateRouting` / `create_v3_routing` |
| DELETE | `/routings` | `deleteNumberRouting` | `DeleteRoutingRequest` | `DeleteRouting` |
| PUT | `/routings/channel` | `createNumberChannelRouting` | `CreateChannelRoutingRequest` | `CreateChannelRouting` |
| POST | `/fax` | `createFax` | `CreateFaxRequest` | `CreateFax` |
| DELETE | `/fax/{faxId}` | `deleteFax` | — | `DeleteFax` |
| PUT | `/fax/{faxId}/alias` | `setAlias` | `SetAliasRequest` | `SetFaxAlias` |
| PUT | `/fax/{faxId}/callerId` | `setCallerId` | `SetCallerIdRequest` | `SetFaxCallerId` |
| PUT | `/fax/{faxId}/tagline` | `setTagline` | `SetTaglineRequest` | `SetFaxTagline` |
| POST | `/faxlines` | `createFaxExtension` | `CreateFaxlineRequest` | `CreateFaxline` / `create_v3_faxline` |
| PUT | `/faxlines/{faxId}/members` | `addFaxMembers` | `AddMembersRequest` | `AddFaxlineMembers` |
| DELETE | `/faxlines/{faxId}/members` | `removeFaxMembers` | `RemoveMembersRequest` | `RemoveFaxlineMembers` |
| PUT | `/voicemails/{voicemailId}/activeGreeting` | `setActiveGreeting` | `SetActiveGreetingRequest` | `SetVoicemailActiveGreeting` |
| PUT | `/voicemails/{voicemailId}/alias` | `renameVoicemail` | `RenameVoicemailRequest` | `RenameVoicemail` |
| PUT | `/voicemails/{voicemailId}/authorizedNumbers` | `changeAuthorizedNumbersForVoicemail` | `SetAuthorizedNumbersForVoicemailRequest` | `SetVoicemailAuthorizedNumbers` |
| DELETE | `/voicemails/{voicemailId}/pin` | `deleteVoicemailPin` | `DeleteVoicemailPinRequest` | `DeleteVoicemailPin` |
| PUT | `/voicemails/{voicemailId}/pin` | `changeVoicemailPin` | `SetVoicemailPinRequest` | `SetVoicemailPin` |
| PUT | `/voicemails/{voicemailId}/transcription` | `setTranscription` | `SetTranscriptionRequest` | `SetVoicemailTranscription` |
| PUT | `/users/{userId}/name` | `changeUserName` | `SetUserNameRequest` | `SetUserName` |
| POST | `/groups` | `createGroup` | `CreateGroupRequest` | `CreateGroup` |
| DELETE | `/groups/{groupId}` | `deleteGroup` | — | `DeleteGroup` |
| PUT | `/groups/{groupId}/alias` | `changeGroupAlias` | `SetGroupAliasRequest` | `SetGroupAlias` |
| POST | `/groups/{groupId}/callqueue` | `createCallQueue` | — | `CreateGroupCallQueue` |
| DELETE | `/groups/{groupId}/callqueue` | `deleteCallThrough` | — | `DeleteGroupCallQueue` |
| PUT | `/groups/{groupId}/callqueue/activeAudioFile` | `setActiveCallQueueAudioFile` | `SetActiveAudioFileRequest` | `SetGroupCallQueueAudio` |
| POST | `/groups/{groupId}/contracts/statistics` | `createContract_2` | `CreateContractRequest` | `CreateGroupStatisticsContract` |
| POST | `/groups/{groupId}/greeting` | `createGreeting` | — | `CreateGroupGreeting` |
| DELETE | `/groups/{groupId}/greeting` | `deleteGreeting` | — | `DeleteGroupGreeting` |
| PUT | `/groups/{groupId}/greeting/activeAudioFile` | `setActiveGreetingAudioFile` | `SetActiveAudioFileRequest` | `SetGroupGreetingAudio` |
| PUT | `/groups/{groupId}/members` | `changeGroupMembers` | `SetGroupMembersRequest` | `SetGroupMembers` |
| POST | `/contracts` | `createContract` | `BookContractRequest` | `BookContract` |
| POST | `/contracts/{contractId}/cancellation` | `cancelContract` | `CancelContractRequest` | `CancelContract` |
| DELETE | `/contracts/{contractId}/cancellation` | `rollbackCancellation` | — | `RevokeContractCancellation` |
| POST | `/trunks/bookMinutes` | `bookMinutes` | `BookTrunkingMinutesRequest` | `BookTrunkMinutes` |
| POST | `/trunks/contracts` | `bookTrunkContract_1` | `BookTrunkContractRequest` | `BookTrunkContract` |
| PUT | `/trunks/contracts` | `bookTrunkContract` | `ChangeTrunkContractRequest` | `ChangeTrunkContract` |
| POST | `/trunks/contracts/cancellation` | `cancelContract_2` | `CancelTrunkContractRequest` | `CancelTrunkContract` |
| DELETE | `/trunks/contracts/cancellation` | `revokeCancellation` | `RevokeCancellationRequest` | `RevokeTrunkContractCancellation` |
| POST | `/trunks/contracts/extension` | `createTrunkExtension` | `CreateTrunkExtensionRequest` | `CreateTrunkExtension` |
| DELETE | `/trunks/{trunkId}` | `deleteTrunk` | — | `DeleteTrunk` |
| PUT | `/trunks/{trunkId}/alias` | `changeTrunkAlias` | `SetTrunkAliasRequest` | `SetTrunkAlias` |
| POST | `/trunks/{trunkId}/credentialsPassword` | `generateNewSipPassword` | — | `GenerateSipPassword` |
| PUT | `/trunks/{trunkId}/emergencyAddressId` | `setEmergencyAddressId` | `SetTrunkEmergencyAddressRequest` | `SetTrunkEmergencyAddress` |
| PUT | `/trunks/{trunkId}/fallbackCallerId` | `setFallbackCallerId` | `SetTrunkFallbackCallerIdRequest` | `SetTrunkFallbackCallerId` |
| POST | `/labels` | `addLabel` | `LabelCreateRequest` | `CreateLabel` |
| PUT | `/labels/{labelId}` | `changeLabel` | `LabelChangeRequest` | `RenameLabel` |
| DELETE | `/labels/{labelId}` | `deleteLabel` | — | `DeleteLabel` |

The request builders preserve the Swagger's camelCase names and required fields,
validate path ids, E.164 values, text, PINs and batch sizes before the wire, and
use `V3AdminResponse` for the heterogeneous success bodies. `DELETE /routings`
and `DELETE /voicemails/{voicemailId}/pin` carry the documented body even though
the verb is `DELETE`. `SynthesizeRequest.type` is a free string in the OpenAPI
schema with no documented meaning; `SynthesizeType` therefore validates and
carries the token, with `Other(String)` for unknown values, and assigns it no
semantics.

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
| GET | `/devices/{deviceId}` | `getDevice` | — | 200 → `DeviceResponse` | `device` |
| GET | `/contacts` | `getContacts_1` | — | 200 → `ContactsResponse` | `contacts` |
| GET | `/contacts/{contactId}` | `getContactById` | — | 200 → `ContactResponse` | `contact` |
| GET | `/history` | `getHistory` | — | 200 → `HistoryResponse` | `history` |
| GET | `/phonelines` | `getAllPhonelines` | — | 200 → `AccountPhonelinesResponse` | `phonelines` |
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
  `datadId` is spelled that way — see §7.4).
* `NewIvrRecordingRequest` / `NewVoicemailRecordingRecordingRequest` —
  `deviceId`, `endpoint`, `targetId`, all optional.
* `Call` / `Participant` — `callId`, `hold`, `muted`, `recording`,
  `participants[]`; participant `participantId`, `phoneNumber` (may be the
  literal `<unknown>`), `hold`, `muted`, `owner`.
* `DeviceResponse` / `ContactResponse` / `HistoryEntryResponse` /
  `AccountPhonelineResponse` — the core REST v2 administration read models are
  typed, with the list envelopes `ContactsResponse`, `HistoryResponse` and
  `AccountPhonelinesResponse`; unknown fields are ignored and unknown enum
  values are carried verbatim.

### 5.1 REST v2 account administration — verified

Issue #181 completes the account-administration tags in the same Swagger
document. Issue #178 was a strict subset of this surface and is collapsed into
#181. The following paths are typed and covered by the mock transport matrix in
`tests/rest.rs`; path ids, query values and bodies are validated before the
wire, list envelopes decode permissively, and unknown response fields remain
available through the typed raw carriers where the schema is open-ended.

* **account** — `GET /account`, `GET /balance`, `PUT /account/verified`.
* **addresses** — `GET /addresses`, `GET /addresses/itemCount`,
  `GET /addresses/{addressId}`, `PUT /addresses/{addressId}`,
  `GET /addresses/{addressId}/numbers`.
* **users** — `GET /users`, `GET /users/{userId}`, `DELETE /users/{userId}`,
  `PUT /users/{userId}/busyonbusy`, `PUT /users/{userId}/defaultdevice`,
  `PUT /users/{userId}/location`.
* **groups** — `GET /groups`, `GET /groups/{groupId}`,
  `POST`/`DELETE /groups/{groupId}/devices[/{deviceId}]`,
  `GET /groups/{groupId}/{faxlines,numbers,users,voicemail}`,
  `GET /groupfaxlines`, `GET /groupfaxlines/{faxlineId}/callerid`, and
  `GET /groupfaxlines/{faxlineId}/numbers`.
* **channels** — `GET /channels`, `DELETE /channels/{channelId}`,
  `GET /channels/{channelId}/events`, `PUT /channels/{channelId}/name`,
  `PUT /channels/{channelId}/users`, and
  `PUT /channels/{channelId}/users/{userId}/devices`.
* **faxlines** — `GET`/`POST /{userId}/faxlines`,
  `DELETE`/`PUT /{userId}/faxlines/{faxlineId}`,
  `GET`/`PUT /{userId}/faxlines/{faxlineId}/callerid`,
  `GET /{userId}/faxlines/{faxlineId}/numbers`, and
  `PUT /{userId}/faxlines/{faxlineId}/tagline`.
* **numbers** — `GET /numbers`, `PUT /numbers/{numberId}`,
  `POST /numbers/quickdial`, `GET /numbers/quickdial/validation/{quickDialNumber}`,
  `DELETE`/`PUT /numbers/quickdial/{numberId}`, and `GET /{userId}/numbers`.
* **voicemails** — `GET /voicemails`, `GET /voicemails/{voicemailId}`.
* **blacklist** — `GET`/`POST /blacklist/incoming`,
  `DELETE /blacklist/incoming/{phoneNumber}`.
* **callrestrictions / restrictions** — `GET /callrestrictions`,
  `POST /{userId}/callrestrictions/{restriction}`, `GET /restrictions`.
* **portings** — `GET /portings`, `GET`/`DELETE /portings/{portingId}`.
* **autorecordings** — `GET`/`POST /autorecordings/greetings`,
  `DELETE /autorecordings/greetings/{greetingId}`,
  `GET`/`PUT /autorecordings/{extension}/settings`.
* **notifications** — `GET`/`DELETE /{userId}/notifications[/{notificationId}]`
  and the eight documented `POST /{userId}/notifications/{call,fax,sms,voicemail}/{email,sms,report}`
  combinations. Each kind validates the fields the Swagger definitions mark
  required before serializing the body.
* **settings** — `GET`/`PUT /settings/sipgateio`.
* **urls / log / app** — `GET /`, `GET /log/webhooks`, `GET /app/events`,
  `DELETE /app/events/{id}`, `GET /app/{links,properties,tacs,users}`, and
  `GET /translations/{language}`.
* **authorization** — `GET /authorization/userinfo`, and
  `GET`/`POST /authorization/oauth2/clients`,
  `GET`/`PUT`/`DELETE /authorization/oauth2/clients/{clientId}`,
  `GET /authorization/oauth2/clients/{clientId}/gdpr`.

The `forwardings` tag is already represented by the typed phoneline forwarding
operations from #167. The separate legacy `sms` caller-id tag and `rtcm` call
control tag remain in §8; the session wrappers for sending SMS and controlling
live calls are already implemented.

Documented error statuses: 400 (invalid request), 402 (insufficient funds), 403
(not allowed), 404 (unknown call), 409 (call not yet established for hold and
transfer), 500.

Error bodies carry no documented schema in v2, so `Error::Api` keeps the raw
body (truncated to 512 bytes) and the status; v3 documents RFC-9457-style
`ProblemDetail` objects for several endpoints, which the same field carries
unchanged.

## 6. Authentication — verified, with one open question

**Flow webhooks** use the shared secret of §3: no OAuth2 on the inbound side.

**REST API v2** takes exactly one of two credentials, and they use *different*
headers (<https://en.sipgate.io/rest-api/authentication>):

| Credential | Header | Documentation |
| --- | --- | --- |
| Personal Access Token (token id + token) | `Authorization: Basic base64(<token id>:<token>)` | "The header takes the keyword Basic followed by a space and a credential string. The credential string is a Base64-encoded combination of your token ID and your token delimited by a colon." |
| OAuth2 access token | `Authorization: Bearer <access_token>` | step 4: "you have to send the access token as authorization header … `Authorization: Bearer …`" |

`sipgateio` 2.15.1 (official Node client) builds both the same way in
`getAuthHeader`: `tokenId` → `Basic base64(id:token)`, `token` → `Bearer`.

That is why `PersonalAccessToken` (Basic) and `StaticToken` (Bearer) are separate
types: sending a PAT as a bearer is *not* the documented path. Earlier drafts of
this file claimed sipgate "also accepts PATs as bearer"; no public source says
that, and the crate no longer assumes it.

**OAuth2 endpoints and capabilities** — verified from the realm's discovery
document
<https://login.sipgate.com/auth/realms/third-party/.well-known/openid-configuration>:

* `token_endpoint` = `https://login.sipgate.com/auth/realms/third-party/protocol/openid-connect/token`
  (identical to the URL in the REST authentication page).
* `grant_types_supported` includes **`client_credentials`** (see §7.5 for what
  that does *not* prove).
* `token_endpoint_auth_methods_supported` includes `client_secret_basic` and
  `client_secret_post`.
* Token responses carry `access_token`, `token_type: "bearer"`, `expires_in:
  300`, `refresh_token`, `session_state`, `not-before-policy` (documented
  example; the refresh token has `refresh_expires_in: 2592000`).

The REST authentication page's own examples post **form-encoded**
`client_id`/`client_secret` (i.e. `client_secret_post`), so that is what
`ClientCredentials::token_request_body` does. The page documents the
authorization-code grant and the refresh-token grant; it does not spell out the
client-credentials request, which is why the grant is quoted from the discovery
document rather than the prose.

**Flow v3** advertises `bearer` plus `oauth2` scopes on `/ai-flows/{id}/call`,
and the SDK sends `Authorization: Bearer <token>`. The v3 document references a
`bearer` security *scheme* that its own `components.securitySchemes` does not
define (only `oauth2` is defined), so which credential that bearer is — an OAuth
access token, or a PAT accepted as bearer by v3 — is not stated anywhere public.
`FlowClient` therefore takes any `TokenSource` and documents the ambiguity rather
than picking one.

Refresh margin: tokens live 300 s; the client treats a token as stale 60 s
before expiry (configurable), and re-fetches on 401 once.

Lifetime ceiling: `expires_in` is an untrusted `u64`, and `Duration` addition
panics on overflow, so `auth::MAX_TOKEN_LIFETIME` (86400 s = 24 h) is the
largest lifetime the crate accepts; anything above it is `Error::TokenResponse`.
That is a defensive maximum, not a documented sipgate value - the only lifetime
the docs state is the 300 s in the discovery example above - and 86400 s is
almost three hundred times that, so a correct endpoint is never affected.

---

## 7. Unverified

These are the shapes I could not confirm from a public source. Each is either
omitted or handled in the tolerant direction, never assumed correct.

### 7.1 Action delivery outside the webhook — unresolvable

The barge-in page says actions work "anywhere an action response is accepted:
HTTP webhook response body, WebSocket message, or external API POST", and the
`configure_transcription` page lists "External API POST" as one of "all three
delivery channels". **No path, method, auth scheme or body envelope is
published.** Searched, in this order:

* the whole flow documentation corpus in one file
  (<https://flow.sipgate.io/llms-full.txt>, 356 KB): "external API" appears three
  times — twice about calling *your* slow API, once as the delivery channel;
* the v3 `OpenAPI` document: 402 paths, none of them an action endpoint
  (`/ai-flows*` is list/CRUD/call/logs/routing/vocabulary/usage; there is no
  `/sessions/{id}/actions`);
* the v3 Swagger (86 paths) and the v2 Swagger;
* `@sipgate/ai-flow-sdk` 2.1.0: its only action transport is the webhook response
  and the WebSocket (`assistant.express()`, `assistant.ws()`).

Conclusion: no client method is implemented. (The 0.1 stub guessed
`POST {base}/calls/{id}/actions`; nothing in either API matches that path.) If
sipgate publishes it, the action types are already transport agnostic and only a
one-method client is missing.

### 7.2 `user_speak.language` — contradicted, carried anyway

The `configure_transcription` page's JavaScript example reads
`const detectedLanguage = event.language; // BCP-47 code from STT`. But:

* the `user_speak` field table lists only `type`, `text`, `barged_in` and the
  session fields;
* `AiFlowEventUserSpeakSchema` in SDK 2.1.0 is `{session, type, text, barged_in}` —
  no `language`;
* `language` appears in that SDK only inside TTS configs and the transcription
  languages array, never on an event.

So `EventPayload::UserSpeak { language }` stays an `Option<String>` fed from the
wire, nothing in the crate branches on it, and a payload without it parses
exactly as documented. Neither the field table nor the SDK is wrong about the
minimum; the example may simply be ahead of, or behind, the schema.

### 7.3 `barge_in.strategy: "immediate"` — resolved, see §2

Kept as a note because this file previously listed it as unverified: the API page
and `BargeInStrategy` in SDK 2.1.0 both contain `immediate`.

### 7.4 `datadId` — the wire key is documented, the server's reading is not

`PlayRecordingRequest` spells the voicemail identifier `datadId`: `swagger.json`
has that property name and **no `dataId` anywhere** in the v2 document. Every
public client that talks to `POST /sessions/voicemail/play` sends `datadId`
(`sipgate-rest-api-client-v2` 5.30.1, `sipgate-mcp` 0.6.0). sipgate's v3
document uses `dataId` for a *different* resource — a history entry, in
`/events/{dataId}/transcribe` — and `voicemailId` for voicemails, which is why
the typo hypothesis is plausible but not provable.

What remains unverified is whether the *service* reads `datadId` or silently
ignores it. Proving that needs an account and a voicemail; the crate sends the
documented key only (never both), so it cannot be wrong in the direction that
duplicates a field. `PlayVoicemail::to_json` is pinned by a unit test against the
schema's own example (`{"datadId": "1000171", "deviceId": "e0"}`).

### 7.5 Client-credentials tokens against user-scoped endpoints — unresolvable

The realm advertises `client_credentials`, but every prose example uses the
authorization-code grant or a PAT, and a client-credentials token represents the
OAuth client rather than a user. Whether `api.sipgate.com/v2` accepts one for
user-scoped endpoints (`sessions:*`, `rtcm:*`) is not stated by any page I could
find, and cannot be tested without an account. Two data points point away from
it: the REST authentication page documents exactly two grants
(`authorization_code`, `refresh_token`), and the community `sipgate-mcp` states
that "API Clients … create OAuth 2.0 client credentials for an application that
redirects users through sipgate's authorization flow. Those client credentials
are not PAT replacements." That last sentence is a user's reading, not a vendor
statement, so it is recorded as evidence, not proof.

`OAuth2Client` therefore still supports the grant (it is advertised, and the
token cache and 401 handling are grant-agnostic), while the README recommends
`PersonalAccessToken` as the documented server-side path.

### 7.6 `transfer` required fields and the `transfer_to` spelling

The field table marks `caller_id_name` and `caller_id_number` as **required**, and
`AiFlowActionTransferSchema` in SDK 2.1.0 agrees (`caller_id_name: z.ZodString`,
not optional), while the `dtmf_received` example sends a transfer as
`{"type":"transfer","session_id":"…","transfer_to":"49211100200"}` — no caller id
and a different field name. The model follows the field table
(`target_phone_number`), keeps the caller-id pair optional so both documented
shapes can be produced, and never emits `transfer_to`, which the field table does
not mention. A caller who wants the two-sources-agree shape sets both ids.

### 7.7 Rate limits on the REST API

No page publishes a numeric limit. What *is* documented: the v3 `OpenAPI`
document declares `429` with a `Retry-After` header ("Seconds until the
applicable limit permits another request") for rate-limited endpoints, and the
`Retry-After` semantics are therefore sipgate's, not this crate's invention. The
client's 429/5xx retry budgets and backoff numbers remain this crate's defaults:
3 attempts, 250 ms doubling, 8 s ceiling.

**No idempotency key exists.** Neither the v2 Swagger, the v3 `OpenAPI`
document nor the SDKs declare an idempotency key, request id or
`Idempotency-Key` header for any write endpoint, and no page promises that a
repeated `POST` collapses into one. That is why a retryable `5xx` or a timeout
after a `POST` is surfaced as `Error::Ambiguous` instead of being retried; the
protocol itself marks `408`/`425` as not processed and `501`/`505` as
permanent. The classification comes from those semantics (see the delivery
contract in the README), not from a provider guarantee that does not exist.

### 7.8 Flow fax / voicemail / recording / DTMF actions

The issue that drove this work listed them as Flow actions. They do not exist in
the Flow action catalogue (`speak`, `audio`, `mix_audio`, `hangup`, `transfer`,
`barge_in`, `configure_transcription`, `send_sms` — confirmed against both the
page and the SDK union). The equivalents live in REST v2 (`/sessions/fax`,
`/sessions/voicemail/*`, `/calls/{id}/dtmf`, `/calls/{id}/recording`) and are
implemented there.

### 7.9 WebSocket handshake authentication — undocumented

<https://flow.sipgate.io/api/websocket> describes the URL
(`wss://your-domain.com/ai-flow/websocket`) and the JSON framing, and nothing
else about trust: no header, token, query parameter, subprotocol or mTLS
requirement appears on the page, in `llms-full.txt` (searched for "websocket",
"auth", "token"), or in `@sipgate/ai-flow-sdk` 2.1.0, whose `ws(ws)` handler
takes an already-established `ws` object and never inspects its handshake.

Consequence for this crate: `flow::socket` implements the message protocol only.
It invents no credential, and it does not claim that a connection is
authentic — whoever accepts the socket owns that decision (a signed URL, a
reverse proxy allow-list, whatever their infrastructure offers). A caller who
finds the mechanism published should put it in front of `Connection`, not inside
the protocol layer.

### 7.10 Push API authentication — undocumented

The Push API reference and overview describe the URL you configure, the form
parameters and the XML reply. Neither page, nor the troubleshooting page, names
a request header, token, signature, HTTP Basic credential or source allow-list;
the overview only recommends HTTPS and notes that self-signed certificates are
rejected. §11 therefore records "none documented", and `push::PushVerifier`
invents none: it checks the content type and a bounded body, and the deployment
owns authentication (an unguessable path, a reverse proxy, a network
allow-list). A caller who finds a published mechanism should put it in front of
the handler, not inside this module.

### 7.11 Duplicate Flow webhook deliveries — caller-owned

The Flow webhook documentation asks receivers to handle duplicate events, but
an event carries no delivery id, there is no `X-Request-ID` or retry-policy
header, and no signature or HMAC protects the body; the documented inbound
credential is the shared `X-API-TOKEN` already checked in constant time by
`WebhookVerifier`. Identical bytes can also be a legitimate repeated input,
such as a caller saying the same word twice. The crate therefore does not
guess identity, deduplicate silently or add a fingerprint/window API for
0.1.0: durable deduplication belongs to the caller and the surrounding
application.

## 8. Surfaces not covered yet

Every surface sipgate documents and this crate does not model is an **open issue**,
not a decision record. A bullet in this section that carries no issue link is a bug
in this document — `tests/docs.rs` fails on it. Order of work is the order below:

* **REST v2 SMS and live-call compatibility administration** — the older
  `/v2/{userId}/sms/...` caller-id tag and `/v2/calls/...` `rtcm` tag in
  <https://api.sipgate.com/v2/swagger.json>. Tracked in
  [#12](https://github.com/floffel/sipgate-flow/issues/12). The session wrapper
  operations are modelled; these separate legacy tags are documented but not
  modelled yet.
* **v3 account inventory** — the same 402-path document; accounts
  (ai-agents and the playground are other products). Tracked in
  [#15](https://github.com/floffel/sipgate-flow/issues/15).
* **v3 device and phoneline inventory** — the same 402-path document; devices
  and phonelines. Tracked in
  [#15](https://github.com/floffel/sipgate-flow/issues/15).

### Absent upstream

Two surfaces are missing from sipgate, not from this crate, so there is nothing to
implement and no issue to track:

* **Action delivery through the Flow "external API POST"** — three sentences in the
  flow documentation mention the channel; neither the docs, the 402 v3 paths, the
  v2/v3 swagger nor `@sipgate/ai-flow-sdk` 2.1.0 names a path, method or body
  envelope. See §7.1.
* **Fax, voicemail, recording and DTMF as *Flow* actions** — absent from the Flow
  action catalogue (§7.8). Their real equivalents are REST v2 operations and are
  implemented: `send_fax`, `resend_fax`, `play_voicemail`, `record_voicemail`,
  `record_ivr`, `set_recording`, `send_dtmf`.

## 9. Source index

| Source | Retrieved | Used for |
| --- | --- | --- |
| <https://api.sipgate.com/v2/swagger.json> | 2026-10-24 | every REST v2 path, request and response shape |
| <https://api.sipgate.com/v3/openapi.json> | 2026-11-05 | outbound call URL, `/ai-webhooks`, `/tts/voices`, DTOs, security, 429/`Retry-After`, `ProblemDetail` |
| <https://api.sipgate.com/v3/swagger.json> | 2026-10-24 | cross-check; still has no `/ai-flows` |
| <https://flow.sipgate.io/llms-full.txt> | 2026-10-24 | the whole flow documentation in one file (searched for "external API", `X-API`, `language`) |
| <https://flow.sipgate.io/api/events> + one page per event | 2026-10-24 | event shapes and enums |
| <https://flow.sipgate.io/api/actions> + one page per action | 2026-10-24 | action shapes and limits |
| <https://flow.sipgate.io/api/tts-providers>, `/api/barge-in`, `/api/vad` | 2026-10-24 | providers, strategies, VAD bounds |
| <https://flow.sipgate.io/api/authentication>, `/api/http-webhooks` | 2026-10-24 | the shared secret and `X-API-TOKEN` |
| <https://flow.sipgate.io/api/websocket> (and `/api/websocket.md`) | 2026-11-05 | the WebSocket channel: framing, the documented ping/pong, the per-event transport table, the absent handshake authentication |
| <https://flow.sipgate.io/api/guides/outbound-calls> | 2026-10-24 | the outbound call flow and its preconditions |
| <https://flow.sipgate.io/sdk/api-reference>, `/sdk/integrations/express` | 2026-10-24 | `baseUrl` default, and the one place `X-API-Key` is written by hand |
| `@sipgate/ai-flow-sdk` 2.1.0 (`registry.npmjs.org` tarball) | 2026-10-24 | event/action schemas, `user_barge_in`, `immediate`, TTS providers, outbound call code |
| `@sipgate/n8n-nodes-ai-flow` 0.3.0 (sipgate GmbH) | 2026-10-24 | first-party webhook consumer: `X-API-TOKEN` default |
| `sipgateio` 2.15.1 | 2026-10-24 | PAT as `Basic id:token`, OAuth as `Bearer` |
| <https://en.sipgate.io/rest-api/authentication> | 2026-10-24 | PAT vs OAuth2 headers, token lifetimes, grant list |
| <https://en.sipgate.io/rest-api/managing-third-party-clients> | 2026-10-24 | what an API client is (redirect URIs, web origins) |
| <https://login.sipgate.com/auth/realms/third-party/.well-known/openid-configuration> | 2026-10-24 | grants, token endpoint auth methods |
| <https://en.sipgate.io/push-api/api-references> | 2026-11-05 | every Push API event parameter, XML verb, attribute, default and limit |
| <https://en.sipgate.io/push-api> + `/troubleshooting` | 2026-11-05 | webhook URL configuration, HTTPS recommendation, transfer/forward behaviour, and the absence of any credential |

## 10. Fixture provenance

| Fixture | Source |
| --- | --- |
| `flow/session_start.json` | <https://flow.sipgate.io/api/events/session-start> (Event Structure) |
| `flow/session_start_transfer_failed.json` | same page (Returning Callers) |
| `flow/user_speech_started.json` | <https://flow.sipgate.io/api/events/user-speech-started> |
| `flow/websocket_message.json` | <https://flow.sipgate.io/api/websocket> (Receiving Events) |
| `flow/user_speak.json`, `flow/user_speak_barged_in.json` | <https://flow.sipgate.io/api/events/user-speak> |
| `flow/user_barge_in.json` | shape from `AiFlowEventUserBargeInSchema` (`@sipgate/ai-flow-sdk` 2.1.0); values synthetic |
| `flow/dtmf_received.json` | <https://flow.sipgate.io/api/events/dtmf-received> |
| `flow/assistant_speak.json` | <https://flow.sipgate.io/api/events/assistant-speak> |
| `flow/assistant_speech_ended.json` | <https://flow.sipgate.io/api/events/assistant-speech-ended> |
| `flow/user_input_timeout.json` | <https://flow.sipgate.io/api/events/user-input-timeout> |
| `flow/session_end.json` | <https://flow.sipgate.io/api/events/session-end> |
| `flow/sms_failed.json` | <https://flow.sipgate.io/api/events#sms-failed> |
| `flow/error.json` | <https://flow.sipgate.io/api/events/error> |
| `flow/unknown_event.json` | synthetic, for the permissive path |
| `push/new_call.form` | the `curl` example in <https://en.sipgate.io/push-api/api-references> (§ The POST request) |
| `push/new_call_diverted.form` | `newCall` field table, with `origCallId`, `xcid` and the optional `diversion` |
| `push/answer.form` | the `curl` example in the *onAnswer* section, same page |
| `push/hangup.form` | the `curl` example in the *onHangup* section, same page |
| `push/dtmf.form`, `push/dtmf_empty.form` | the `curl` example in the *onData* section plus its "empty if no input" note |
| `push/unknown_event.form` | synthetic, for the permissive path |
| `rest/*_request.json` | `definitions` examples in <https://api.sipgate.com/v2/swagger.json> |
| `rest/calls_response.json` | `Call` / `Participant` definitions, same document |

## 11. Classic Push API — verified

Sources: <https://en.sipgate.io/push-api/api-references> (parameters, verbs,
attributes, defaults and limits) and <https://en.sipgate.io/push-api> (webhook
configuration, transfer/forward behaviour, HTTPS recommendation), retrieved
**2026-11-05**. This is a different protocol from Flow: form-encoded in, XML
out, no JSON anywhere.

**Inbound.** sipgate.io POSTs `application/x-www-form-urlencoded` to the URL
configured under *sipgate.io → Webhooks → Incoming/Outgoing calls*. The
reference's parameter tables give one event per body:

| `event` | Documented parameters | Modelled as |
| --- | --- | --- |
| `newCall` | `from`, `to`, `direction` (`in`/`out`), `callId`, `origCallId`, `user[]`, `userId[]`, `fullUserId[]`, `xcid`; optional `diversion` | `PushEventKind::NewCall` |
| `answer` | `callId`, `user`, `userId`, `fullUserId`, `from`, `to`, `direction`, `answeringNumber`; optional `diversion` | `PushEventKind::Answer` |
| `hangup` | `callId`, `cause`, `from`, `to`, `direction`, `answeringNumber`; optional `diversion` | `PushEventKind::Hangup` |
| `dtmf` | `callId`, `dtmf` | `PushEventKind::Dtmf` |

`from` may be the literal `anonymous`. `user[]` is always spelled with the
brackets when repeated, and a group call carries one entry per user. The
reference contradicts itself on `dtmf` when nothing was pressed: the *Gather*
section says the field is "completely omitted", the callback table says it is
empty. The model therefore keeps `None` (absent) and `Some("")` (present and
empty) distinguishable and rejects neither. The seven `hangup` causes are
`normalClearing`, `busy`, `cancel`, `noAnswer`, `congestion`, `notFound` and
`forwarded` (`HangupCause`).

**Outbound.** The reply is XML and the reference requires
`Content-Type: application/xml`; every example also opens with
`<?xml version="1.0" encoding="UTF-8"?>`. The root element is `<Response>` and
carries the optional `onAnswer` and `onHangup` subscription URLs (follow-up
events arrive as `answer`/`hangup` bodies).

| Verb | Documented shape | Modelled as |
| --- | --- | --- |
| `Dial` | attributes `callerId` (E.164) and `anonymous` (`true`/`false`); children `<Number>` (E.164) or `<Voicemail />`; "calls with `direction=in` can be redirected to up to 5 targets" | `Dial`, `DialTarget` |
| `Play` | `<Url>` with an absolute URL; the file must be mono 16-bit PCM WAV at 8 kHz | `Play` |
| `Gather` | attributes `type` (`dtmf`, the default), `onData` (mandatory absolute URL), `maxDigits` (integer >= 1, default 1), `timeout` (ms, integer >= 1, default 2000); `<Play>` may be nested inside | `Gather` |
| `Reject` | attribute `reason` (`rejected`, the default, or `busy`) | `RejectReason` |
| `Hangup` | no attributes | `PushAction::Hangup` |

The reference states no upper bound for `maxDigits` or `timeout`, so the crate
uses `u32` and applies no ceiling below the documented `1`. The five-target cap
is applied to every `Dial`, because a response does not state which direction it
answers. The reference's nesting list for `Gather` renders empty on the page and
its only `<Gather>` example nests `<Play>`, so `Gather` exposes exactly that.

**Authentication: none documented.** See §7.10. `PushVerifier` enforces the
documented content type and a crate-imposed body ceiling
(`MAX_PUSH_BODY_BYTES`, 64 KiB, checked before the form is decoded); it invents
no header, token or signature.
