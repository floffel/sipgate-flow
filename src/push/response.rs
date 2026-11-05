//! What a Push API handler answers with: an XML `<Response>` document.
//!
//! The reference (<https://en.sipgate.io/push-api/api-references>) documents
//! five verbs — `Dial`, `Play`, `Gather`, `Reject`, `Hangup` — plus two
//! attributes on the `<Response>` element itself (`onAnswer`, `onHangup`) that
//! subscribe the handler to follow-up events. Every builder in this module
//! returns [`Result`], so a [`PushResponse`] always renders XML the service can
//! read: there is no "validated at serialisation time" state to forget.
//!
//! ```rust
//! use sipgate_flow::push::{Dial, PushAction, PushResponse};
//!
//! let response = PushResponse::new()
//!     .with_on_hangup("https://example.com/hangup")?
//!     .with_verb(PushAction::dial(Dial::to_number("4915799912345")?));
//! assert_eq!(response.status(), 200);
//! assert_eq!(response.content_type(), "application/xml");
//! assert!(response
//!     .to_xml()
//!     .contains("<Dial><Number>4915799912345</Number></Dial>"));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use crate::error::{Error, Result};
use crate::validate;

/// How many `<Number>`/`<Voicemail>` targets one `<Dial>` may carry.
///
/// The reference says "Calls with `direction=in` can be redirected to up to 5
/// targets", so the sixth target is refused instead of sending a document the
/// service would cut off. The cap applies to every dial this crate builds,
/// because the response does not say which direction it answers.
///
/// ```rust
/// use sipgate_flow::push::{Dial, MAX_DIAL_TARGETS};
///
/// assert_eq!(MAX_DIAL_TARGETS, 5);
///
/// let mut dial = Dial::to_number("4915799912341")?;
/// for number in ["4915799912342", "4915799912343", "4915799912344"] {
///     dial = dial.with_number(number)?;
/// }
/// assert_eq!(dial.targets().len(), 4);
///
/// let five = dial.with_number("4915799912345")?;
/// assert!(five.with_number("4915799912346").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
pub const MAX_DIAL_TARGETS: usize = 5;

/// The documented default for a `<Gather>`'s `maxDigits` attribute.
///
/// ```rust
/// use sipgate_flow::push::DEFAULT_GATHER_MAX_DIGITS;
///
/// assert_eq!(DEFAULT_GATHER_MAX_DIGITS, 1);
/// ```
pub const DEFAULT_GATHER_MAX_DIGITS: u32 = 1;

/// The documented default for a `<Gather>`'s `timeout` attribute, in
/// milliseconds.
///
/// ```rust
/// use sipgate_flow::push::DEFAULT_GATHER_TIMEOUT_MS;
///
/// assert_eq!(DEFAULT_GATHER_TIMEOUT_MS, 2_000);
/// ```
pub const DEFAULT_GATHER_TIMEOUT_MS: u32 = 2_000;

/// The document a Push API webhook answers with.
///
/// The empty response is valid: the reference's verbs are optional, and an
/// answer without one lets the call proceed normally.
///
/// ```rust
/// use sipgate_flow::push::PushResponse;
///
/// let response = PushResponse::new();
/// assert_eq!(
///     response.to_xml(),
///     "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response />"
/// );
/// assert!(response.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushResponse {
    on_answer: Option<String>,
    on_hangup: Option<String>,
    verbs: Vec<PushAction>,
}

impl PushResponse {
    /// A response with no verb and no subscriptions.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes to the `answer` follow-up event on this URL.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// let response = PushResponse::new().with_on_answer("https://example.com/answer")?;
    /// assert_eq!(response.on_answer(), Some("https://example.com/answer"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an absolute `http(s)` URL
    /// without credentials.
    pub fn with_on_answer(mut self, url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        validate::http_url("response.onAnswer", &url)?;
        self.on_answer = Some(url);
        Ok(self)
    }

    /// Subscribes to the `hangup` follow-up event on this URL.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// let response = PushResponse::new().with_on_hangup("https://example.com/hangup")?;
    /// assert_eq!(response.on_hangup(), Some("https://example.com/hangup"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an absolute `http(s)` URL
    /// without credentials.
    pub fn with_on_hangup(mut self, url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        validate::http_url("response.onHangup", &url)?;
        self.on_hangup = Some(url);
        Ok(self)
    }

    /// Appends one verb; verbs are rendered in the order they were added.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushAction, PushResponse};
    ///
    /// let response = PushResponse::new()
    ///     .with_verb(PushAction::hangup())
    ///     .with_verb(PushAction::hangup());
    /// assert_eq!(response.len(), 2);
    /// ```
    #[must_use]
    pub fn with_verb(mut self, action: PushAction) -> Self {
        self.verbs.push(action);
        self
    }

    /// The verbs, in order.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushAction, PushResponse};
    ///
    /// let response = PushResponse::new().with_verb(PushAction::hangup());
    /// assert_eq!(response.verbs()[0].verb(), "Hangup");
    /// ```
    #[must_use]
    pub fn verbs(&self) -> &[PushAction] {
        &self.verbs
    }

    /// The `onAnswer` subscription, when one was set.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().on_answer(), None);
    /// ```
    #[must_use]
    pub fn on_answer(&self) -> Option<&str> {
        self.on_answer.as_deref()
    }

    /// The `onHangup` subscription, when one was set.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().on_hangup(), None);
    /// ```
    #[must_use]
    pub fn on_hangup(&self) -> Option<&str> {
        self.on_hangup.as_deref()
    }

    /// How many verbs the response carries.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.verbs.len()
    }

    /// Whether the response carries no verb.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert!(PushResponse::new().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.verbs.is_empty()
    }

    /// The HTTP status a framework should send. Always `200`: the document is
    /// the instruction, and an empty `<Response />` is a valid one.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().status(), 200);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        200
    }

    /// The `Content-Type` the reference requires.
    ///
    /// The reference tells the handler to set `application/xml` in the
    /// response's `Content-Type` header. The value is part of the type so a
    /// handler cannot forget it.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushResponse;
    ///
    /// assert_eq!(PushResponse::new().content_type(), "application/xml");
    /// ```
    #[must_use]
    pub fn content_type(&self) -> &'static str {
        "application/xml"
    }

    /// Renders the XML document.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushAction, PushResponse};
    ///
    /// let response = PushResponse::new().with_verb(PushAction::hangup());
    /// assert_eq!(
    ///     response.to_xml(),
    ///     "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Hangup /></Response>"
    /// );
    /// ```
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response");
        push_attribute(&mut out, "onAnswer", self.on_answer.as_deref());
        push_attribute(&mut out, "onHangup", self.on_hangup.as_deref());
        if self.verbs.is_empty() {
            out.push_str(" />");
            return out;
        }
        out.push('>');
        for verb in &self.verbs {
            verb.write_xml(&mut out);
        }
        out.push_str("</Response>");
        out
    }
}

impl From<PushAction> for PushResponse {
    fn from(action: PushAction) -> Self {
        Self {
            verbs: vec![action],
            ..Self::default()
        }
    }
}

/// One verb inside the `<Response>` element.
///
/// ```rust
/// use sipgate_flow::push::{PushAction, RejectReason};
///
/// assert_eq!(PushAction::hangup().verb(), "Hangup");
/// assert_eq!(PushAction::reject(RejectReason::Busy).verb(), "Reject");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushAction {
    /// Send the call to one or more numbers, or to voicemail.
    Dial(Dial),
    /// Play a sound file from a URL.
    Play(Play),
    /// Collect keypad digits and report them to a callback URL.
    Gather(Gather),
    /// Reject the call, optionally pretending to be busy.
    Reject(RejectReason),
    /// Hang up the call.
    Hangup,
}

impl PushAction {
    /// Wraps a [`Dial`].
    ///
    /// ```rust
    /// use sipgate_flow::push::{Dial, PushAction};
    ///
    /// let dial = Dial::to_number("4915799912345")?;
    /// assert_eq!(PushAction::dial(dial).verb(), "Dial");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn dial(dial: Dial) -> Self {
        Self::Dial(dial)
    }

    /// Wraps a [`Play`].
    ///
    /// ```rust
    /// use sipgate_flow::push::{Play, PushAction};
    ///
    /// let play = Play::new("https://example.com/example.wav")?;
    /// assert_eq!(PushAction::play(play).verb(), "Play");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn play(play: Play) -> Self {
        Self::Play(play)
    }

    /// Wraps a [`Gather`].
    ///
    /// ```rust
    /// use sipgate_flow::push::{Gather, PushAction};
    ///
    /// let gather = Gather::new("https://example.com/dtmf")?;
    /// assert_eq!(PushAction::gather(gather).verb(), "Gather");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn gather(gather: Gather) -> Self {
        Self::Gather(gather)
    }

    /// Rejects the call.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushAction, RejectReason};
    ///
    /// assert_eq!(PushAction::reject(RejectReason::Busy).verb(), "Reject");
    /// ```
    #[must_use]
    pub fn reject(reason: RejectReason) -> Self {
        Self::Reject(reason)
    }

    /// Hangs up the call.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushAction;
    ///
    /// assert_eq!(PushAction::hangup().verb(), "Hangup");
    /// ```
    #[must_use]
    pub fn hangup() -> Self {
        Self::Hangup
    }

    /// The XML element name of this verb.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushAction;
    ///
    /// assert_eq!(PushAction::hangup().verb(), "Hangup");
    /// ```
    #[must_use]
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Dial(_) => "Dial",
            Self::Play(_) => "Play",
            Self::Gather(_) => "Gather",
            Self::Reject(_) => "Reject",
            Self::Hangup => "Hangup",
        }
    }

    /// Writes this verb into `out`.
    fn write_xml(&self, out: &mut String) {
        match self {
            Self::Dial(dial) => dial.write_xml(out),
            Self::Play(play) => play.write_xml(out),
            Self::Gather(gather) => gather.write_xml(out),
            Self::Reject(reason) => {
                out.push_str("<Reject reason=\"");
                out.push_str(reason.as_str());
                out.push_str("\" />");
            }
            Self::Hangup => out.push_str("<Hangup />"),
        }
    }
}

/// Why a call was rejected.
///
/// The reference documents exactly two values, so the enum carries exactly
/// two; `#[non_exhaustive]` leaves room for a value sipgate adds later.
///
/// ```rust
/// use sipgate_flow::push::RejectReason;
///
/// assert_eq!(RejectReason::Rejected.as_str(), "rejected");
/// assert_eq!(RejectReason::Busy.as_str(), "busy");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// The call is rejected; this is the documented default.
    Rejected,
    /// The caller hears a busy signal.
    Busy,
}

impl RejectReason {
    /// The wire value.
    ///
    /// ```rust
    /// use sipgate_flow::push::RejectReason;
    ///
    /// assert_eq!(RejectReason::Rejected.as_str(), "rejected");
    /// assert_eq!(RejectReason::Busy.as_str(), "busy");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Busy => "busy",
        }
    }
}

/// One `<Dial>` target: an external number or the account's voicemail.
///
/// The type has no public constructor that accepts an unvalidated number, so a
/// `<Number>` element this crate renders is always E.164 digits.
///
/// ```rust
/// use sipgate_flow::push::DialTarget;
///
/// assert_eq!(DialTarget::number("+4915799912345")?.as_number(), Some("4915799912345"));
/// assert!(DialTarget::voicemail().is_voicemail());
/// assert!(DialTarget::number("491579").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialTarget {
    kind: DialTargetKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DialTargetKind {
    Number(String),
    Voicemail,
}

impl DialTarget {
    /// An external number.
    ///
    /// ```rust
    /// use sipgate_flow::push::DialTarget;
    ///
    /// let target = DialTarget::number("4915799912345")?;
    /// assert_eq!(target.as_number(), Some("4915799912345"));
    /// assert!(!target.is_voicemail());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not E.164 digits. An optional
    /// leading `+` is accepted and stripped, because the reference's examples
    /// use the bare digits.
    pub fn number(value: impl Into<String>) -> Result<Self> {
        let number = validate::phone("dial.number", &value.into())?;
        Ok(Self {
            kind: DialTargetKind::Number(number),
        })
    }

    /// The account's voicemail, if the feature is booked.
    ///
    /// ```rust
    /// use sipgate_flow::push::DialTarget;
    ///
    /// assert!(DialTarget::voicemail().is_voicemail());
    /// assert_eq!(DialTarget::voicemail().as_number(), None);
    /// ```
    #[must_use]
    pub fn voicemail() -> Self {
        Self {
            kind: DialTargetKind::Voicemail,
        }
    }

    /// The number, when this target is one.
    ///
    /// ```rust
    /// use sipgate_flow::push::DialTarget;
    ///
    /// assert_eq!(
    ///     DialTarget::number("4915799912345")?.as_number(),
    ///     Some("4915799912345")
    /// );
    /// assert_eq!(DialTarget::voicemail().as_number(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn as_number(&self) -> Option<&str> {
        match &self.kind {
            DialTargetKind::Number(number) => Some(number),
            DialTargetKind::Voicemail => None,
        }
    }

    /// Whether this target is the voicemail.
    ///
    /// ```rust
    /// use sipgate_flow::push::DialTarget;
    ///
    /// assert!(DialTarget::voicemail().is_voicemail());
    /// assert!(!DialTarget::number("4915799912345")?.is_voicemail());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn is_voicemail(&self) -> bool {
        matches!(self.kind, DialTargetKind::Voicemail)
    }

    /// Writes this target into `out`.
    fn write_xml(&self, out: &mut String) {
        match &self.kind {
            DialTargetKind::Number(number) => {
                out.push_str("<Number>");
                out.push_str(&escape(number));
                out.push_str("</Number>");
            }
            DialTargetKind::Voicemail => out.push_str("<Voicemail />"),
        }
    }
}

/// A `<Dial>` verb: redirect the call, optionally changing the caller id.
///
/// A dial without a target is not constructible: the first target is the
/// constructor, so the type cannot render `<Dial></Dial>`.
///
/// ```rust
/// use sipgate_flow::push::Dial;
///
/// let dial = Dial::to_number("4915799912345")?
///     .with_number("492111234567")?
///     .with_caller_id("492111234567")?
///     .with_anonymous(true);
/// assert_eq!(dial.targets().len(), 2);
/// assert_eq!(dial.caller_id(), Some("492111234567"));
/// assert_eq!(dial.anonymous(), Some(true));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dial {
    caller_id: Option<String>,
    anonymous: Option<bool>,
    targets: Vec<DialTarget>,
}

impl Dial {
    /// Starts a dial to an external number.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// let dial = Dial::to_number("+4915799912345")?;
    /// assert_eq!(dial.to_xml(), "<Dial><Number>4915799912345</Number></Dial>");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the number is not E.164 digits (an optional
    /// leading `+` is accepted and stripped, because the reference's examples
    /// use the bare digits).
    pub fn to_number(number: impl Into<String>) -> Result<Self> {
        Ok(Self {
            caller_id: None,
            anonymous: None,
            targets: vec![DialTarget::number(number)?],
        })
    }

    /// Starts a dial to the account's voicemail.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// assert_eq!(Dial::to_voicemail().to_xml(), "<Dial><Voicemail /></Dial>");
    /// ```
    #[must_use]
    pub fn to_voicemail() -> Self {
        Self {
            caller_id: None,
            anonymous: None,
            targets: vec![DialTarget::voicemail()],
        }
    }

    /// Adds another target; the first destination to pick up is connected.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// let dial = Dial::to_number("4915799912345")?.with_number("492111234567")?;
    /// assert_eq!(dial.targets().len(), 2);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the target would be the sixth (see
    /// [`MAX_DIAL_TARGETS`]) or when the number is not E.164.
    pub fn with_number(mut self, number: impl Into<String>) -> Result<Self> {
        self.push(DialTarget::number(number)?)?;
        Ok(self)
    }

    /// Adds the account's voicemail as another target.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// let dial = Dial::to_number("4915799912345")?.with_voicemail()?;
    /// assert_eq!(
    ///     dial.to_xml(),
    ///     "<Dial><Number>4915799912345</Number><Voicemail /></Dial>"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the target would be the sixth, or when the
    /// dial already targets the voicemail.
    pub fn with_voicemail(mut self) -> Result<Self> {
        self.push(DialTarget::voicemail())?;
        Ok(self)
    }

    /// Sets the number shown to the callee.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// let dial = Dial::to_number("4915799912345")?.with_caller_id("492111234567")?;
    /// assert_eq!(dial.caller_id(), Some("492111234567"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not E.164 digits.
    pub fn with_caller_id(mut self, number: impl Into<String>) -> Result<Self> {
        self.caller_id = Some(validate::phone("dial.callerId", &number.into())?);
        Ok(self)
    }

    /// Hides or shows the caller id. Without this call the account and phone
    /// settings decide, which is what the reference documents as the default.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// let dial = Dial::to_number("4915799912345")?.with_anonymous(true);
    /// assert_eq!(
    ///     dial.to_xml(),
    ///     "<Dial anonymous=\"true\"><Number>4915799912345</Number></Dial>"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = Some(anonymous);
        self
    }

    /// The configured caller id, when one was set.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// assert_eq!(Dial::to_voicemail().caller_id(), None);
    /// ```
    #[must_use]
    pub fn caller_id(&self) -> Option<&str> {
        self.caller_id.as_deref()
    }

    /// The anonymity setting, when one was set.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// assert_eq!(Dial::to_voicemail().anonymous(), None);
    /// ```
    #[must_use]
    pub fn anonymous(&self) -> Option<bool> {
        self.anonymous
    }

    /// The targets, in order.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// assert_eq!(Dial::to_voicemail().targets().len(), 1);
    /// ```
    #[must_use]
    pub fn targets(&self) -> &[DialTarget] {
        &self.targets
    }

    /// Renders the verb, without the surrounding `<Response>`.
    ///
    /// ```rust
    /// use sipgate_flow::push::Dial;
    ///
    /// assert_eq!(Dial::to_voicemail().to_xml(), "<Dial><Voicemail /></Dial>");
    /// ```
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write_xml(&mut out);
        out
    }

    /// Appends one target, enforcing the documented ceiling.
    fn push(&mut self, target: DialTarget) -> Result<()> {
        if self.targets.len() >= MAX_DIAL_TARGETS {
            return Err(Error::validation(
                "dial.targets",
                format!("a Dial can carry at most {MAX_DIAL_TARGETS} targets"),
            ));
        }
        if target.is_voicemail() && self.targets.iter().any(DialTarget::is_voicemail) {
            return Err(Error::validation(
                "dial.targets",
                "the voicemail can only be dialled once",
            ));
        }
        self.targets.push(target);
        Ok(())
    }

    /// Writes the verb into `out`.
    fn write_xml(&self, out: &mut String) {
        out.push_str("<Dial");
        push_attribute(out, "callerId", self.caller_id.as_deref());
        if let Some(anonymous) = self.anonymous {
            out.push_str(" anonymous=\"");
            out.push_str(if anonymous { "true" } else { "false" });
            out.push('"');
        }
        out.push('>');
        for target in &self.targets {
            target.write_xml(out);
        }
        out.push_str("</Dial>");
    }
}

/// A `<Play>` verb: play a sound file from a URL.
///
/// The reference requires mono 16-bit PCM WAV at 8 kHz. The file is fetched by
/// sipgate, not by this crate, so the format cannot be checked here — use
/// [`crate::wav::validate_pcm16`] on the bytes you serve, with a rate of 8000
/// and one channel, if the clip is generated rather than recorded.
///
/// ```rust
/// use sipgate_flow::push::Play;
///
/// let play = Play::new("https://example.com/greeting.wav")?;
/// assert_eq!(play.to_xml(), "<Play><Url>https://example.com/greeting.wav</Url></Play>");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Play {
    url: String,
}

impl Play {
    /// Points at a sound file.
    ///
    /// ```rust
    /// use sipgate_flow::push::Play;
    ///
    /// let play = Play::new("https://example.com/a.wav?v=1&size=2")?;
    /// assert_eq!(
    ///     play.to_xml(),
    ///     "<Play><Url>https://example.com/a.wav?v=1&amp;size=2</Url></Play>"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is not an absolute `http(s)` URL
    /// without credentials, or contains whitespace or control characters.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        validate::http_url("play.url", &url)?;
        Ok(Self { url })
    }

    /// The URL the clip is fetched from.
    ///
    /// ```rust
    /// use sipgate_flow::push::Play;
    ///
    /// assert_eq!(
    ///     Play::new("https://example.com/a.wav")?.url(),
    ///     "https://example.com/a.wav"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Renders the verb, without the surrounding `<Response>`.
    ///
    /// ```rust
    /// use sipgate_flow::push::Play;
    ///
    /// assert!(Play::new("https://example.com/a.wav")?.to_xml().starts_with("<Play>"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write_xml(&mut out);
        out
    }

    /// Writes the verb into `out`.
    fn write_xml(&self, out: &mut String) {
        out.push_str("<Play><Url>");
        out.push_str(&escape(&self.url));
        out.push_str("</Url></Play>");
    }
}

/// A `<Gather>` verb: collect keypad digits and report them to a callback URL.
///
/// The defaults are the documented ones: `maxDigits` 1 and `timeout` 2000 ms.
/// Both are written out explicitly, so the document says what it means instead
/// of relying on a default. The reference's nesting list renders empty on the
/// page and its only `<Gather>` example nests `<Play>`, which
/// [`Gather::with_play`] provides.
///
/// ```rust
/// use sipgate_flow::push::Gather;
///
/// let gather = Gather::new("https://example.com/dtmf")?
///     .with_max_digits(3)?
///     .with_timeout_ms(10_000)?;
/// assert_eq!(
///     gather.to_xml(),
///     "<Gather onData=\"https://example.com/dtmf\" type=\"dtmf\" maxDigits=\"3\" timeout=\"10000\" />"
/// );
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gather {
    on_data: String,
    max_digits: u32,
    timeout_ms: u32,
    play: Option<Play>,
}

impl Gather {
    /// Starts a gather that reports to `on_data`.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// let gather = Gather::new("https://example.com/dtmf")?;
    /// assert_eq!(gather.max_digits(), 1);
    /// assert_eq!(gather.timeout_ms(), 2_000);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `on_data` is not an absolute `http(s)` URL
    /// without credentials. The reference marks the attribute as mandatory, and
    /// without it the collected digits are lost.
    pub fn new(on_data: impl Into<String>) -> Result<Self> {
        let on_data = on_data.into();
        validate::http_url("gather.onData", &on_data)?;
        Ok(Self {
            on_data,
            max_digits: DEFAULT_GATHER_MAX_DIGITS,
            timeout_ms: DEFAULT_GATHER_TIMEOUT_MS,
            play: None,
        })
    }

    /// Sets how many digits are collected before the event fires.
    ///
    /// The reference documents `maxDigits` as an integer `>= 1` and states no
    /// upper bound, so [`u32::MAX`] is accepted: the type's width is the only
    /// ceiling this crate applies.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// let gather = Gather::new("https://example.com/dtmf")?;
    /// assert!(gather.clone().with_max_digits(1).is_ok());
    /// assert!(gather.clone().with_max_digits(u32::MAX).is_ok());
    /// assert!(gather.with_max_digits(0).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0`, the one value the reference excludes.
    pub fn with_max_digits(mut self, max_digits: u32) -> Result<Self> {
        if max_digits == 0 {
            return Err(Error::validation(
                "gather.maxDigits",
                "must be at least 1 digit",
            ));
        }
        self.max_digits = max_digits;
        Ok(self)
    }

    /// Sets how long the service waits for input, in milliseconds.
    ///
    /// The reference documents `timeout` as an integer `>= 1` with a default of
    /// 2000 ms and states no upper bound. The timeout starts after the prompt
    /// has finished playing; the first digit stops playback.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// let gather = Gather::new("https://example.com/dtmf")?;
    /// assert!(gather.clone().with_timeout_ms(1).is_ok());
    /// assert!(gather.clone().with_timeout_ms(u32::MAX).is_ok());
    /// assert!(gather.with_timeout_ms(0).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for `0`, the one value the reference excludes.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Result<Self> {
        if timeout_ms == 0 {
            return Err(Error::validation(
                "gather.timeout",
                "must be at least 1 millisecond",
            ));
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    /// Nests a prompt inside the gather. The reference's example nests exactly
    /// one `<Play>`, and playback stops as soon as the first digit arrives.
    ///
    /// ```rust
    /// use sipgate_flow::push::{Gather, Play};
    ///
    /// let gather = Gather::new("https://example.com/dtmf")?
    ///     .with_play(Play::new("https://example.com/menu.wav")?);
    /// assert!(gather
    ///     .to_xml()
    ///     .contains("<Play><Url>https://example.com/menu.wav</Url></Play>"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_play(mut self, play: Play) -> Self {
        self.play = Some(play);
        self
    }

    /// The callback URL the digits are posted to.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// assert_eq!(
    ///     Gather::new("https://example.com/dtmf")?.on_data(),
    ///     "https://example.com/dtmf"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn on_data(&self) -> &str {
        &self.on_data
    }

    /// The configured digit count.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// assert_eq!(Gather::new("https://example.com/dtmf")?.max_digits(), 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn max_digits(&self) -> u32 {
        self.max_digits
    }

    /// The configured timeout, in milliseconds.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// assert_eq!(Gather::new("https://example.com/dtmf")?.timeout_ms(), 2_000);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// The nested prompt, when one was set.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// assert!(Gather::new("https://example.com/dtmf")?.play().is_none());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn play(&self) -> Option<&Play> {
        self.play.as_ref()
    }

    /// Renders the verb, without the surrounding `<Response>`.
    ///
    /// ```rust
    /// use sipgate_flow::push::Gather;
    ///
    /// assert!(Gather::new("https://example.com/dtmf")?.to_xml().starts_with("<Gather "));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write_xml(&mut out);
        out
    }

    /// Writes the verb into `out`.
    fn write_xml(&self, out: &mut String) {
        out.push_str("<Gather");
        push_attribute(out, "onData", Some(&self.on_data));
        out.push_str(" type=\"dtmf\" maxDigits=\"");
        out.push_str(&self.max_digits.to_string());
        out.push_str("\" timeout=\"");
        out.push_str(&self.timeout_ms.to_string());
        out.push('"');
        match &self.play {
            Some(play) => {
                out.push('>');
                play.write_xml(out);
                out.push_str("</Gather>");
            }
            None => out.push_str(" />"),
        }
    }
}

/// Writes ` name="value"` when `value` is present.
fn push_attribute(out: &mut String, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        out.push_str(&escape(value));
        out.push('"');
    }
}

/// Escapes the five XML metacharacters, so no value can leave its slot.
///
/// Every value that reaches this function has already passed a validator that
/// refuses whitespace and control characters, so the result is XML 1.0 text.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_dial_accepts_five_targets_and_refuses_the_sixth() {
        let five = Dial::to_number("4915799912341")
            .and_then(|dial| dial.with_number("4915799912342"))
            .and_then(|dial| dial.with_number("4915799912343"))
            .and_then(|dial| dial.with_number("4915799912344"))
            .and_then(|dial| dial.with_number("4915799912345"))
            .expect("five targets are documented");
        assert_eq!(five.targets().len(), MAX_DIAL_TARGETS);
        assert_eq!(five.to_xml().matches("<Number>").count(), MAX_DIAL_TARGETS);

        let error = five
            .with_number("4915799912346")
            .expect_err("the sixth target exceeds the documented ceiling");
        assert!(
            matches!(
                error,
                Error::Validation {
                    field: "dial.targets",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_dial_starts_with_exactly_one_target() {
        let dial = Dial::to_number("4915799912345").expect("a valid number");
        assert_eq!(dial.targets().len(), 1);
        assert_eq!(dial.targets()[0].as_number(), Some("4915799912345"));
        assert!(Dial::to_voicemail().targets()[0].is_voicemail());
    }

    #[test]
    fn a_voicemail_target_cannot_be_repeated() {
        let dial = Dial::to_voicemail();
        assert!(dial.clone().with_voicemail().is_err());
        assert!(dial.with_number("4915799912345").is_ok());
    }

    #[test]
    fn a_number_is_normalised_to_the_documented_digits() {
        assert_eq!(
            Dial::to_number("+4915799912345")
                .expect("a leading + is stripped")
                .targets()[0]
                .as_number(),
            Some("4915799912345")
        );
        // Six digits is one below the E.164 minimum; sixteen one above the
        // maximum. Seven and fifteen are accepted.
        assert!(Dial::to_number("4915799").is_ok());
        assert!(Dial::to_number("491579991234567").is_ok());
        for bad in [
            "",
            "+",
            "491579",
            "004915799912345",
            "4915799912345678",
            "abd",
        ] {
            assert!(Dial::to_number(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_gather_boundaries_are_one_and_the_numeric_width() {
        let gather = Gather::new("https://example.com/dtmf").expect("a valid URL");
        assert!(gather.clone().with_max_digits(1).is_ok());
        assert!(gather.clone().with_max_digits(u32::MAX).is_ok());
        assert!(gather.clone().with_max_digits(0).is_err());
        assert!(gather.clone().with_timeout_ms(1).is_ok());
        assert!(gather.clone().with_timeout_ms(u32::MAX).is_ok());
        assert!(gather.with_timeout_ms(0).is_err());
    }

    #[test]
    fn a_gather_renders_its_defaults_explicitly() {
        let gather = Gather::new("https://example.com/dtmf").expect("a valid URL");
        assert_eq!(
            gather.to_xml(),
            "<Gather onData=\"https://example.com/dtmf\" type=\"dtmf\" maxDigits=\"1\" timeout=\"2000\" />"
        );
    }

    #[test]
    fn a_url_cannot_leave_its_attribute_or_text_node() {
        let play =
            Play::new("https://example.com/a.wav?x=\"<&>'\"").expect("a query is not a slot");
        let xml = play.to_xml();
        assert!(!xml.contains("x=\"<"), "{xml}");
        assert!(xml.contains("&quot;&lt;&amp;&gt;&apos;"), "{xml}");
    }

    #[test]
    fn a_response_renders_every_verb_in_order() {
        let response = PushResponse::new()
            .with_on_answer("https://example.com/answer")
            .expect("a valid URL")
            .with_on_hangup("https://example.com/hangup")
            .expect("a valid URL")
            .with_verb(PushAction::play(
                Play::new("https://example.com/a.wav").expect("a valid URL"),
            ))
            .with_verb(PushAction::reject(RejectReason::Rejected))
            .with_verb(PushAction::hangup());
        assert_eq!(
            response.to_xml(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Response onAnswer=\"https://example.com/answer\" onHangup=\"https://example.com/hangup\">\
             <Play><Url>https://example.com/a.wav</Url></Play>\
             <Reject reason=\"rejected\" />\
             <Hangup />\
             </Response>"
        );
        assert_eq!(response.status(), 200);
        assert_eq!(response.content_type(), "application/xml");
    }

    #[test]
    fn the_subscription_urls_are_validated() {
        for bad in [
            "",
            "/relative",
            "ftp://example.com/x",
            "https://u:p@example.com/x",
        ] {
            assert!(
                PushResponse::new().with_on_answer(bad).is_err(),
                "onAnswer {bad:?}"
            );
            assert!(
                PushResponse::new().with_on_hangup(bad).is_err(),
                "onHangup {bad:?}"
            );
        }
    }

    #[test]
    fn every_accessor_reports_what_was_built() {
        let play = Play::new("https://example.com/a.wav").expect("a valid URL");
        assert_eq!(play.url(), "https://example.com/a.wav");

        let gather = Gather::new("https://example.com/dtmf")
            .expect("a valid URL")
            .with_max_digits(4)
            .expect("four digits are documented")
            .with_timeout_ms(500)
            .expect("500 ms is documented")
            .with_play(play.clone());
        assert_eq!(gather.on_data(), "https://example.com/dtmf");
        assert_eq!(gather.max_digits(), 4);
        assert_eq!(gather.timeout_ms(), 500);
        assert_eq!(gather.play(), Some(&play));
        assert!(gather.to_xml().contains("maxDigits=\"4\""));

        let dial = Dial::to_number("4915799912345")
            .expect("a valid number")
            .with_caller_id("492111234567")
            .expect("a valid caller id")
            .with_anonymous(false);
        assert_eq!(dial.caller_id(), Some("492111234567"));
        assert_eq!(dial.anonymous(), Some(false));
        assert_eq!(dial.targets().len(), 1);
        assert!(dial.to_xml().contains("anonymous=\"false\""));

        assert_eq!(DialTarget::voicemail().as_number(), None);
        assert_eq!(
            DialTarget::number("4915799912345")
                .expect("valid")
                .as_number(),
            Some("4915799912345")
        );

        let response = PushResponse::new()
            .with_on_answer("https://example.com/answer")
            .expect("a valid URL")
            .with_on_hangup("https://example.com/hangup")
            .expect("a valid URL")
            .with_verb(PushAction::dial(dial))
            .with_verb(PushAction::play(play))
            .with_verb(PushAction::gather(gather))
            .with_verb(PushAction::reject(RejectReason::Busy))
            .with_verb(PushAction::hangup());
        assert_eq!(response.on_answer(), Some("https://example.com/answer"));
        assert_eq!(response.on_hangup(), Some("https://example.com/hangup"));
        assert_eq!(response.len(), 5);
        assert!(!response.is_empty());
        assert_eq!(
            response
                .verbs()
                .iter()
                .map(PushAction::verb)
                .collect::<Vec<_>>(),
            ["Dial", "Play", "Gather", "Reject", "Hangup"]
        );
    }

    #[test]
    fn a_single_action_becomes_a_one_verb_response() {
        let response: PushResponse = PushAction::hangup().into();
        assert_eq!(response.len(), 1);
        assert_eq!(
            response.to_xml(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Hangup /></Response>"
        );
    }

    proptest! {
        /// Whatever text reaches a URL or an attribute, it cannot terminate the
        /// slot it sits in: no raw metacharacter survives escaping.
        #[test]
        fn escaping_removes_every_metacharacter(value in ".{0,64}") {
            let escaped = escape(&value);
            let mut probe = escaped.clone();
            for entity in ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"] {
                probe = probe.replace(entity, "");
            }
            prop_assert!(!probe.contains(['<', '>', '"', '\'', '&']), "{escaped}");
        }
    }
}
