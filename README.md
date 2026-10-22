# sipgate-flow

Typed, **tolerant** client for sipgate's voice-flow API.

The API is only partially documented, so this crate never fails on the parts we
do not model: unknown events become `Event::Unknown` instead of parse errors,
and unknown fields are ignored. That makes it safe to ship against an API that
adds event types over time.

```rust
let event = Event::parse(body)?;
if let Some(call_id) = event.call_id() {
    client.execute(call_id, &Action::say("Willkommen!")).await?;
}
```

`SipgateFlowClient` takes the base URL explicitly — the exact endpoint path is
not byte-documented, so guessing it inside the crate would bake in a wrong
assumption.

Licensed under Apache-2.0 OR MIT.
