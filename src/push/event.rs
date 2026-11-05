//! Inbound Push API events, decoded from `application/x-www-form-urlencoded`.
//!
//! The classic sipgate.io Push API posts one form-encoded body per call event
//! to the URL configured under *sipgate.io → Webhooks*
//! (<https://en.sipgate.io/push-api/api-references>). Four events are
//! documented — `newCall`, `answer`, `hangup` and `dtmf` — and they share one
//! shape: a `callId`, the two numbers, the direction, and a few fields only
//! one of them carries (`cause`, `dtmf`, `answeringNumber`). [`PushEvent`]
//! models that with one type and a [`PushEventKind`], instead of four payload
//! structs that would repeat `callId`/`from`/`to`.
//!
//! Decoding is tolerant in the direction the wire can drift: unknown fields
//! are preserved ([`PushEvent::extra`]), an unrecognised `event` value becomes
//! [`PushEventKind::Unknown`], `user[]` may be repeated (that is how the
//! reference describes a group call) or appear once as `user`, and parameter
//! names are matched ignoring ASCII case, `_` and `-`, so `callId` and
//! `call_id` are the same field. A *known* scalar parameter that arrives twice
//! is a typed error instead of a guess.
//!
//! ```rust
//! use sipgate_flow::push::{PushDirection, PushEvent, PushEventKind};
//!
//! let event = PushEvent::parse(
//!     b"event=newCall&direction=in&from=492111234567&to=4915791234567&callId=123456",
//! )?;
//! assert_eq!(event.kind(), &PushEventKind::NewCall);
//! assert_eq!(event.direction(), Some(&PushDirection::In));
//! assert_eq!(event.call_id(), Some("123456"));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Largest form body [`PushEvent::parse`] accepts, in bytes.
///
/// Real Push API bodies are a few hundred bytes. The ceiling is checked before
/// the form is decoded, so a caller cannot force a large allocation through
/// [`PushEvent::parse`] or [`crate::push::PushVerifier`].
///
/// ```rust
/// assert_eq!(sipgate_flow::push::MAX_PUSH_BODY_BYTES, 64 * 1024);
/// ```
pub const MAX_PUSH_BODY_BYTES: usize = 64 * 1024;

/// Which documented Push API event arrived.
///
/// The reference sends `newCall`, `answer`, `hangup` and `dtmf` in the `event`
/// parameter. Matching ignores ASCII case and the separators `_` and `-`, so
/// `newCall`, `new_call` and `NEWCALL` are the same kind; an unrecognised
/// value is carried verbatim.
///
/// ```rust
/// use sipgate_flow::push::PushEventKind;
///
/// assert_eq!(PushEventKind::from_wire("newCall"), PushEventKind::NewCall);
/// assert_eq!(PushEventKind::from_wire("new_call"), PushEventKind::NewCall);
/// assert!(matches!(
///     PushEventKind::from_wire("callWaiting"),
///     PushEventKind::Unknown(_)
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushEventKind {
    /// `event=newCall`: a call has started, inbound or outbound.
    NewCall,
    /// `event=answer`: the call was answered.
    Answer,
    /// `event=hangup`: the call ended.
    Hangup,
    /// `event=dtmf`: a `<Gather>` completed and the digits are in the body.
    Dtmf,
    /// An `event` value this crate does not model yet, kept verbatim.
    Unknown(String),
}

impl PushEventKind {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEventKind;
    ///
    /// assert_eq!(PushEventKind::from_wire("answer"), PushEventKind::Answer);
    /// assert_eq!(PushEventKind::from_wire("HANGUP"), PushEventKind::Hangup);
    /// assert_eq!(
    ///     PushEventKind::from_wire("callWaiting"),
    ///     PushEventKind::Unknown("callWaiting".into())
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match normalize(value).as_str() {
            "newcall" => Self::NewCall,
            "answer" => Self::Answer,
            "hangup" => Self::Hangup,
            "dtmf" => Self::Dtmf,
            _ => Self::Unknown(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEventKind;
    ///
    /// assert_eq!(PushEventKind::NewCall.as_str(), "newCall");
    /// assert_eq!(PushEventKind::Unknown("callWaiting".into()).as_str(), "callWaiting");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::NewCall => "newCall",
            Self::Answer => "answer",
            Self::Hangup => "hangup",
            Self::Dtmf => "dtmf",
            Self::Unknown(value) => value,
        }
    }
}

/// Call direction, as reported in the `direction` parameter.
///
/// The Push API documents exactly `in` and `out`; a value outside that pair is
/// carried as [`PushDirection::Other`] instead of failing the parse.
///
/// ```rust
/// use sipgate_flow::push::PushDirection;
///
/// assert_eq!(PushDirection::from_wire("in"), PushDirection::In);
/// assert_eq!(PushDirection::Out.as_str(), "out");
/// assert!(matches!(
///     PushDirection::from_wire("sideways"),
///     PushDirection::Other(_)
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushDirection {
    /// The caller dialled in.
    In,
    /// The account placed the call.
    Out,
    /// A value this crate does not model yet, kept verbatim.
    Other(String),
}

impl PushDirection {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushDirection;
    ///
    /// assert_eq!(PushDirection::from_wire("IN"), PushDirection::In);
    /// assert!(matches!(
    ///     PushDirection::from_wire("sideways"),
    ///     PushDirection::Other(_)
    /// ));
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match normalize(value).as_str() {
            "in" => Self::In,
            "out" => Self::Out,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushDirection;
    ///
    /// assert_eq!(PushDirection::In.as_str(), "in");
    /// assert_eq!(PushDirection::Other("sideways".into()).as_str(), "sideways");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::In => "in",
            Self::Out => "out",
            Self::Other(value) => value,
        }
    }
}

/// Why a call ended, from the `hangup` event's `cause` parameter.
///
/// The seven values are the ones the reference's hangup-cause table lists. An
/// unknown cause is carried instead of failing the parse.
///
/// ```rust
/// use sipgate_flow::push::HangupCause;
///
/// assert_eq!(HangupCause::from_wire("normalClearing"), HangupCause::NormalClearing);
/// assert_eq!(HangupCause::from_wire("no_answer"), HangupCause::NoAnswer);
/// assert_eq!(HangupCause::Busy.as_str(), "busy");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HangupCause {
    /// One participant hung up after the call was established.
    NormalClearing,
    /// The called party was busy.
    Busy,
    /// The caller hung up before the called party picked up.
    Cancel,
    /// The called party rejected the call, for example through do-not-disturb.
    NoAnswer,
    /// The called party could not be reached.
    Congestion,
    /// The called number does not exist, or the called party is offline.
    NotFound,
    /// The call was forwarded to a different party.
    Forwarded,
    /// A value this crate does not model yet, kept verbatim.
    Other(String),
}

impl HangupCause {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```rust
    /// use sipgate_flow::push::HangupCause;
    ///
    /// assert_eq!(HangupCause::from_wire("notFound"), HangupCause::NotFound);
    /// assert!(matches!(HangupCause::from_wire("meteor"), HangupCause::Other(_)));
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match normalize(value).as_str() {
            "normalclearing" => Self::NormalClearing,
            "busy" => Self::Busy,
            "cancel" => Self::Cancel,
            "noanswer" => Self::NoAnswer,
            "congestion" => Self::Congestion,
            "notfound" => Self::NotFound,
            "forwarded" => Self::Forwarded,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```rust
    /// use sipgate_flow::push::HangupCause;
    ///
    /// assert_eq!(HangupCause::NormalClearing.as_str(), "normalClearing");
    /// assert_eq!(HangupCause::Other("meteor".into()).as_str(), "meteor");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::NormalClearing => "normalClearing",
            Self::Busy => "busy",
            Self::Cancel => "cancel",
            Self::NoAnswer => "noAnswer",
            Self::Congestion => "congestion",
            Self::NotFound => "notFound",
            Self::Forwarded => "forwarded",
            Self::Other(value) => value,
        }
    }
}

/// One decoded Push API event.
///
/// The accessors are typed views on the parameter map; a field the body did
/// not carry reads as [`None`] rather than being guessed.
///
/// ```rust
/// use sipgate_flow::push::PushEvent;
///
/// let event = PushEvent::parse(
///     b"event=hangup&cause=normalClearing&callId=123456&from=492111234567",
/// )?;
/// assert_eq!(event.call_id(), Some("123456"));
/// assert_eq!(
///     event.cause().map(sipgate_flow::push::HangupCause::as_str),
///     Some("normalClearing")
/// );
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEvent {
    kind: PushEventKind,
    event_name: String,
    call_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    direction: Option<PushDirection>,
    answering_number: Option<String>,
    diversion: Option<String>,
    orig_call_id: Option<String>,
    xcid: Option<String>,
    users: Vec<String>,
    user_ids: Vec<String>,
    full_user_ids: Vec<String>,
    cause: Option<HangupCause>,
    dtmf: Option<String>,
    extra: BTreeMap<String, String>,
}

impl PushEvent {
    /// Decodes a form-encoded event body.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=dtmf&dtmf=1&callId=54566B15")?;
    /// assert_eq!(event.dtmf(), Some("1"));
    ///
    /// // The gather callback always fires, even when no digit arrived.
    /// let empty = PushEvent::parse(b"event=dtmf&dtmf=&callId=54566B15")?;
    /// assert_eq!(empty.dtmf(), Some(""));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::BodyTooLarge`] when the body exceeds [`MAX_PUSH_BODY_BYTES`],
    /// [`Error::EmptyBody`] for an empty or whitespace-only body, and
    /// [`Error::Form`] when the body is not decodable form data, carries no
    /// `event` parameter, or sends a scalar parameter twice.
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() > MAX_PUSH_BODY_BYTES {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: MAX_PUSH_BODY_BYTES,
            });
        }
        if body.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::EmptyBody);
        }

        let mut fields = Fields::default();
        for (key, value) in decode_form(body)? {
            fields.assign(&key, value)?;
        }
        Self::from_fields(fields)
    }

    fn from_fields(fields: Fields) -> Result<Self> {
        let event_name = fields
            .event
            .ok_or_else(|| Error::form("body carries no `event` parameter"))?;
        Ok(Self {
            kind: PushEventKind::from_wire(&event_name),
            event_name,
            call_id: fields.call_id,
            from: fields.from,
            to: fields.to,
            direction: fields.direction.as_deref().map(PushDirection::from_wire),
            answering_number: fields.answering_number,
            diversion: fields.diversion,
            orig_call_id: fields.orig_call_id,
            xcid: fields.xcid,
            users: fields.users,
            user_ids: fields.user_ids,
            full_user_ids: fields.full_user_ids,
            cause: fields.cause.as_deref().map(HangupCause::from_wire),
            dtmf: fields.dtmf,
            extra: fields.extra,
        })
    }

    /// The typed event kind.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushEvent, PushEventKind};
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1")?;
    /// assert_eq!(event.kind(), &PushEventKind::NewCall);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn kind(&self) -> &PushEventKind {
        &self.kind
    }

    /// The `event` value exactly as it arrived.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=NEWCALL&callId=1")?;
    /// assert_eq!(event.event_name(), "NEWCALL");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    /// The call this event belongs to, when the body carried one.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=answer&callId=123456")?;
    /// assert_eq!(event.call_id(), Some("123456"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    /// The calling number, or the literal `anonymous` the reference documents.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&from=anonymous&callId=1")?;
    /// assert_eq!(event.from(), Some("anonymous"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn from(&self) -> Option<&str> {
        self.from.as_deref()
    }

    /// The called number.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&to=4915791234567&callId=1")?;
    /// assert_eq!(event.to(), Some("4915791234567"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to(&self) -> Option<&str> {
        self.to.as_deref()
    }

    /// The call direction, when the body carried one.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushDirection, PushEvent};
    ///
    /// let event = PushEvent::parse(b"event=newCall&direction=out&callId=1")?;
    /// assert_eq!(event.direction(), Some(&PushDirection::Out));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn direction(&self) -> Option<&PushDirection> {
        self.direction.as_ref()
    }

    /// The destination that answered, useful when a call was redirected to
    /// several numbers.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=answer&callId=1&answeringNumber=21199999999")?;
    /// assert_eq!(event.answering_number(), Some("21199999999"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn answering_number(&self) -> Option<&str> {
        self.answering_number.as_deref()
    }

    /// The originally dialled number, when the call was diverted before it
    /// reached sipgate.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&diversion=492111234567")?;
    /// assert_eq!(event.diversion(), Some("492111234567"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn diversion(&self) -> Option<&str> {
        self.diversion.as_deref()
    }

    /// The call this one was transferred from, when the body carried
    /// `origCallId`.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=2&origCallId=1")?;
    /// assert_eq!(event.orig_call_id(), Some("1"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn orig_call_id(&self) -> Option<&str> {
        self.orig_call_id.as_deref()
    }

    /// The second identifier the reference calls `xcid`.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&xcid=x-1")?;
    /// assert_eq!(event.xcid(), Some("x-1"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn xcid(&self) -> Option<&str> {
        self.xcid.as_deref()
    }

    /// The sipgate users involved, in wire order.
    ///
    /// A group call sends one `user[]` per participant; the `answer` and
    /// `hangup` events document a single `user`. Both spellings land here.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let group = PushEvent::parse(b"event=newCall&callId=1&user%5B%5D=Alice&user%5B%5D=Bob")?;
    /// assert_eq!(group.users(), ["Alice", "Bob"]);
    ///
    /// let single = PushEvent::parse(b"event=answer&callId=1&user=Alice")?;
    /// assert_eq!(single.users(), ["Alice"]);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn users(&self) -> &[String] {
        &self.users
    }

    /// The sipgate user ids involved, in wire order (`userId[]`).
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&userId%5B%5D=w0")?;
    /// assert_eq!(event.user_ids(), ["w0"]);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn user_ids(&self) -> &[String] {
        &self.user_ids
    }

    /// The full user ids involved, in wire order (`fullUserId[]`).
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&fullUserId%5B%5D=1234567w0")?;
    /// assert_eq!(event.full_user_ids(), ["1234567w0"]);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn full_user_ids(&self) -> &[String] {
        &self.full_user_ids
    }

    /// Why the call ended, on a `hangup` event.
    ///
    /// ```rust
    /// use sipgate_flow::push::{HangupCause, PushEvent};
    ///
    /// let event = PushEvent::parse(b"event=hangup&cause=busy&callId=1")?;
    /// assert_eq!(event.cause(), Some(&HangupCause::Busy));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn cause(&self) -> Option<&HangupCause> {
        self.cause.as_ref()
    }

    /// The digits a `<Gather>` collected.
    ///
    /// The reference contradicts itself on the empty case: one table says the
    /// parameter is omitted when the caller pressed nothing, the other says it
    /// is empty. Both decode, and they stay distinguishable — `None` when the
    /// parameter was absent, `Some("")` when it was present and empty.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let digits = PushEvent::parse(b"event=dtmf&dtmf=1234&callId=1")?;
    /// assert_eq!(digits.dtmf(), Some("1234"));
    ///
    /// let absent = PushEvent::parse(b"event=newCall&callId=1")?;
    /// assert_eq!(absent.dtmf(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn dtmf(&self) -> Option<&str> {
        self.dtmf.as_deref()
    }

    /// A parameter this crate does not model, by wire key.
    ///
    /// Unknown parameters are kept verbatim; when one arrives twice, the first
    /// value is the one reachable here — the crate never guesses which of two
    /// different values the service meant.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&futureField=42")?;
    /// assert_eq!(event.extra("futureField"), Some("42"));
    /// assert_eq!(event.extra("missing"), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn extra(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(String::as_str)
    }

    /// Every unmodelled parameter, keyed by the wire spelling.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushEvent;
    ///
    /// let event = PushEvent::parse(b"event=newCall&callId=1&futureField=42")?;
    /// assert_eq!(event.extras().len(), 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn extras(&self) -> &BTreeMap<String, String> {
        &self.extra
    }
}

/// Folds ASCII case and drops `_`, `-`, spaces and one trailing `[]` so both
/// the documented spelling and the tolerated one reach the same slot.
fn normalize(value: &str) -> String {
    let trimmed = value.trim();
    let name = trimmed.strip_suffix("[]").unwrap_or(trimmed);
    name.chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// The parameters of one body while it is being decoded.
#[derive(Default)]
struct Fields {
    event: Option<String>,
    call_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    direction: Option<String>,
    answering_number: Option<String>,
    diversion: Option<String>,
    orig_call_id: Option<String>,
    xcid: Option<String>,
    users: Vec<String>,
    user_ids: Vec<String>,
    full_user_ids: Vec<String>,
    cause: Option<String>,
    dtmf: Option<String>,
    extra: BTreeMap<String, String>,
}

impl Fields {
    /// Routes one decoded parameter into its slot.
    fn assign(&mut self, key: &str, value: String) -> Result<()> {
        match normalize(key).as_str() {
            "event" => Self::once(&mut self.event, "event", value),
            "callid" => Self::once(&mut self.call_id, "callId", value),
            "from" => Self::once(&mut self.from, "from", value),
            "to" => Self::once(&mut self.to, "to", value),
            "direction" => Self::once(&mut self.direction, "direction", value),
            "answeringnumber" => Self::once(&mut self.answering_number, "answeringNumber", value),
            "diversion" => Self::once(&mut self.diversion, "diversion", value),
            "origcallid" | "originalcallid" => {
                Self::once(&mut self.orig_call_id, "origCallId", value)
            }
            "xcid" => Self::once(&mut self.xcid, "xcid", value),
            "cause" => Self::once(&mut self.cause, "cause", value),
            "dtmf" => Self::once(&mut self.dtmf, "dtmf", value),
            "user" | "users" => {
                self.users.push(value);
                Ok(())
            }
            "userid" | "userids" => {
                self.user_ids.push(value);
                Ok(())
            }
            "fulluserid" | "fulluserids" => {
                self.full_user_ids.push(value);
                Ok(())
            }
            _ => {
                self.extra.entry(key.to_owned()).or_insert(value);
                Ok(())
            }
        }
    }

    /// Stores a scalar parameter once, refusing a duplicate.
    fn once(slot: &mut Option<String>, field: &'static str, value: String) -> Result<()> {
        if slot.is_some() {
            return Err(Error::form(format!("`{field}` was sent twice")));
        }
        *slot = Some(value);
        Ok(())
    }
}

/// Splits a form body into decoded key/value pairs, in wire order.
fn decode_form(body: &[u8]) -> Result<Vec<(String, String)>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::form("body is not valid UTF-8"))?;
    let mut fields = Vec::new();
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.is_empty() {
            continue;
        }
        fields.push((decode_component(key)?, decode_component(value)?));
    }
    Ok(fields)
}

/// Decodes one `application/x-www-form-urlencoded` component.
fn decode_component(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_digit);
                let low = bytes.get(index + 2).copied().and_then(hex_digit);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(Error::form(
                        "a percent escape is not followed by two hex digits",
                    ));
                };
                out.push((high << 4) | low);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::form("a percent escape does not form UTF-8"))
}

/// The value of one hexadecimal digit.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn parses(body: &str) -> PushEvent {
        PushEvent::parse(body.as_bytes()).expect("a decodable body")
    }

    #[test]
    fn a_new_call_carries_every_documented_field() {
        let event = parses(
            "event=newCall&from=492111234567&to=4915791234567&direction=in\
             &callId=123456&origCallId=999&xcid=x-1&diversion=49211000\
             &user%5B%5D=Alice&user%5B%5D=Bob&userId%5B%5D=w0&userId%5B%5D=w1\
             &fullUserId%5B%5D=1234567w0&fullUserId%5B%5D=1234567w1",
        );
        assert_eq!(event.kind(), &PushEventKind::NewCall);
        assert_eq!(event.call_id(), Some("123456"));
        assert_eq!(event.from(), Some("492111234567"));
        assert_eq!(event.to(), Some("4915791234567"));
        assert_eq!(event.direction(), Some(&PushDirection::In));
        assert_eq!(event.orig_call_id(), Some("999"));
        assert_eq!(event.xcid(), Some("x-1"));
        assert_eq!(event.diversion(), Some("49211000"));
        assert_eq!(event.users(), ["Alice", "Bob"]);
        assert_eq!(event.user_ids(), ["w0", "w1"]);
        assert_eq!(event.full_user_ids(), ["1234567w0", "1234567w1"]);
        assert!(event.extras().is_empty());
    }

    #[test]
    fn snake_case_and_camel_case_name_the_same_parameter() {
        let camel = parses("event=answer&callId=1&answeringNumber=2&origCallId=3");
        let snake = parses("event=answer&call_id=1&answering_number=2&orig_call_id=3");
        assert_eq!(camel, snake);
        assert_eq!(snake.answering_number(), Some("2"));
        assert_eq!(snake.orig_call_id(), Some("3"));
    }

    #[test]
    fn an_answer_event_carries_a_single_user() {
        let event = parses(
            "event=answer&callId=123456&user=John+Doe&userId=w0\
             &fullUserId=1234567w0&from=492111234567&to=4915791234567\
             &direction=in&answeringNumber=21199999999",
        );
        assert_eq!(event.kind(), &PushEventKind::Answer);
        assert_eq!(event.users(), ["John Doe"]);
        assert_eq!(event.user_ids(), ["w0"]);
        assert_eq!(event.full_user_ids(), ["1234567w0"]);
        assert_eq!(event.answering_number(), Some("21199999999"));
    }

    #[test]
    fn a_hangup_event_carries_its_cause() {
        let event = parses("event=hangup&cause=noAnswer&callId=123456&direction=out");
        assert_eq!(event.kind(), &PushEventKind::Hangup);
        assert_eq!(event.cause(), Some(&HangupCause::NoAnswer));
    }

    #[test]
    fn a_dtmf_event_distinguishes_absent_from_empty() {
        let digits = parses("event=dtmf&dtmf=1&callId=123456");
        assert_eq!(digits.dtmf(), Some("1"));

        let empty = parses("event=dtmf&dtmf=&callId=123456");
        assert_eq!(empty.dtmf(), Some(""));

        let absent = parses("event=dtmf&callId=123456");
        assert_eq!(absent.dtmf(), None);
    }

    #[test]
    fn every_kind_and_direction_renders_its_canonical_value() {
        assert_eq!(PushEventKind::NewCall.as_str(), "newCall");
        assert_eq!(PushEventKind::Answer.as_str(), "answer");
        assert_eq!(PushEventKind::Hangup.as_str(), "hangup");
        assert_eq!(PushEventKind::Dtmf.as_str(), "dtmf");
        assert_eq!(
            PushEventKind::Unknown("callWaiting".into()).as_str(),
            "callWaiting"
        );

        assert_eq!(PushDirection::In.as_str(), "in");
        assert_eq!(PushDirection::Out.as_str(), "out");
        assert_eq!(PushDirection::Other("sideways".into()).as_str(), "sideways");
    }

    #[test]
    fn an_unknown_event_keeps_its_name_and_fields() {
        let event = parses("event=callWaiting&callId=1&queue=7");
        assert_eq!(event.kind(), &PushEventKind::Unknown("callWaiting".into()));
        assert_eq!(event.event_name(), "callWaiting");
        assert_eq!(event.extra("queue"), Some("7"));
    }

    #[test]
    fn every_documented_hangup_cause_round_trips() {
        for cause in [
            "normalClearing",
            "busy",
            "cancel",
            "noAnswer",
            "congestion",
            "notFound",
            "forwarded",
        ] {
            assert_eq!(HangupCause::from_wire(cause).as_str(), cause);
        }
        assert_eq!(
            HangupCause::from_wire("normal_clearing").as_str(),
            "normalClearing"
        );
        assert!(matches!(
            HangupCause::from_wire("meteor"),
            HangupCause::Other(value) if value == "meteor"
        ));
    }

    #[test]
    fn duplicates_of_a_scalar_field_are_refused() {
        let error = PushEvent::parse(b"event=newCall&event=hangup")
            .expect_err("two event fields cannot both be right");
        assert!(matches!(error, Error::Form { .. }), "{error:?}");
        assert!(error.to_string().contains("event"), "{error}");
        assert!(PushEvent::parse(b"event=newCall&callId=1&callId=2").is_err());
        // The alias spelling is the same slot, so it cannot smuggle a second value.
        assert!(PushEvent::parse(b"event=newCall&callId=1&call_id=2").is_err());
    }

    #[test]
    fn duplicates_of_a_list_field_are_kept_in_order() {
        let event = parses("event=newCall&user%5B%5D=A&user%5B%5D=B&user=B&user%5B%5D=C");
        assert_eq!(event.users(), ["A", "B", "B", "C"]);
    }

    #[test]
    fn unknown_fields_keep_their_first_value() {
        let event = parses("event=newCall&future=1&future=2&Other=3");
        assert_eq!(event.extra("future"), Some("1"));
        assert_eq!(event.extra("Other"), Some("3"));
        assert_eq!(event.extras().len(), 2);
    }

    #[test]
    fn a_missing_event_field_is_an_error() {
        let error = PushEvent::parse(b"callId=1").expect_err("no event to classify");
        assert!(matches!(error, Error::Form { .. }), "{error:?}");
    }

    #[test]
    fn an_empty_or_blank_body_is_empty_not_malformed() {
        assert!(matches!(PushEvent::parse(b""), Err(Error::EmptyBody)));
        assert!(matches!(
            PushEvent::parse(b"  \r\n\t"),
            Err(Error::EmptyBody)
        ));
    }

    #[test]
    fn a_body_at_the_limit_parses_and_one_byte_over_does_not() {
        let prefix = "event=newCall&pad=";
        let fill = MAX_PUSH_BODY_BYTES - prefix.len();
        let exact = format!("{prefix}{}", "a".repeat(fill));
        assert_eq!(exact.len(), MAX_PUSH_BODY_BYTES);
        assert_eq!(parses(&exact).extra("pad").map(str::len), Some(fill));

        let over = format!("{prefix}{}", "a".repeat(fill + 1));
        assert_eq!(over.len(), MAX_PUSH_BODY_BYTES + 1);
        assert!(matches!(
            PushEvent::parse(over.as_bytes()),
            Err(Error::BodyTooLarge { size, limit })
                if size == MAX_PUSH_BODY_BYTES + 1 && limit == MAX_PUSH_BODY_BYTES
        ));
    }

    #[test]
    fn percent_escapes_decode_to_utf8() {
        let event = parses("event=newCall&callId=%E2%82%AC&from=%2B49211");
        assert_eq!(event.call_id(), Some("€"));
        assert_eq!(event.from(), Some("+49211"));

        let lowercase = parses("event=newCall&callId=%e2%82%ac");
        assert_eq!(lowercase.call_id(), Some("€"));
    }

    #[test]
    fn the_tolerated_list_and_id_aliases_name_the_same_slots() {
        let event = parses(
            "event=newCall&users[]=A&userids[]=w0&fulluserids[]=1234567w0\
             &originalcallid=7",
        );
        assert_eq!(event.users(), ["A"]);
        assert_eq!(event.user_ids(), ["w0"]);
        assert_eq!(event.full_user_ids(), ["1234567w0"]);
        assert_eq!(event.orig_call_id(), Some("7"));
    }

    #[test]
    fn malformed_percent_escapes_are_refused() {
        for body in [
            "event=newCall&callId=%",
            "event=newCall&callId=%4",
            "event=newCall&callId=%zz",
            "event=newCall&callId=%4g",
            "event=newCall&callId=%E2%82",
        ] {
            let error = PushEvent::parse(body.as_bytes()).expect_err(body);
            assert!(matches!(error, Error::Form { .. }), "{body}: {error:?}");
        }
    }

    #[test]
    fn a_body_that_is_not_utf8_is_refused() {
        assert!(matches!(
            PushEvent::parse(b"event=newCall&callId=\xff"),
            Err(Error::Form { .. })
        ));
    }

    #[test]
    fn a_valueless_key_is_an_empty_value() {
        let event = parses("event=newCall&callId&diversion=");
        assert_eq!(event.call_id(), Some(""));
        assert_eq!(event.diversion(), Some(""));
    }

    #[test]
    fn empty_segments_and_empty_keys_are_skipped() {
        let event = parses("&&event=newCall&&=x&callId=1&");
        assert_eq!(event.kind(), &PushEventKind::NewCall);
        assert_eq!(event.call_id(), Some("1"));
        assert!(event.extras().is_empty());
    }

    /// The encoder a browser or sipgate would use: unreserved characters stay,
    /// a space becomes `+`, everything else is a percent escape.
    fn encode(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b' ' => "+".to_owned(),
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    char::from(byte).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect()
    }

    proptest! {
        /// Decoding is the exact inverse of encoding for arbitrary text, so no
        /// value can be mangled on the way in.
        #[test]
        fn percent_decoding_round_trips(value in ".{0,48}") {
            prop_assert_eq!(
                decode_component(&encode(&value)).expect("our own encoding decodes"),
                value.clone()
            );
            let body = format!("event=newCall&callId={}", encode(&value));
            let event = PushEvent::parse(body.as_bytes()).expect("a decodable body");
            prop_assert_eq!(event.call_id(), Some(value.as_str()));
        }

        /// Arbitrary bytes never panic the parser: an error is a fine answer.
        #[test]
        fn parsing_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = PushEvent::parse(&bytes);
        }

        /// Every known parameter survives a round trip through the form
        /// decoder, whatever its value.
        #[test]
        fn a_scalar_parameter_keeps_arbitrary_utf8(value in ".{0,32}") {
            let body = format!("event=answer&answeringNumber={}", encode(&value));
            let event = PushEvent::parse(body.as_bytes()).expect("a decodable body");
            prop_assert_eq!(event.answering_number(), Some(value.as_str()));
        }
    }
}
