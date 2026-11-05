//! The WebSocket transport: Flow opens one link per call, you answer on it.
//!
//! <https://flow.sipgate.io/api/websocket> documents the channel: when a call
//! starts, the Flow service opens a WebSocket connection **to your server** and
//! then streams the same events the webhook delivers, one JSON text message per
//! event. A handler answers by sending actions back as JSON messages, in the
//! same flat shape the webhook response body uses. Because Flow is the
//! connector, this crate ships the *server* half: [`Connection`] is the socket
//! you already own (your `axum`/`tokio-tungstenite`/`tungstenite` handler),
//! [`FlowSocket`] turns its frames into typed [`Event`]s and typed
//! [`Action`]s back, and [`AcceptBackoff`] paces the accept loop that keeps
//! your endpoint reachable.
//!
//! Only `user_speech_started` is exclusive to this transport; every other event
//! is documented as `HTTP + WebSocket`, so the type tree is the same one
//! [`crate::Event`] already models. Actions travel as a single object (one
//! action) or an array (several, executed in order) exactly like a webhook
//! body — [`FlowResponse`] renders both, which keeps a handler transport
//! independent.
//!
//! ```
//! # #[cfg(feature = "websocket")]
//! # fn main() -> Result<(), sipgate_flow::Error> {
//! use sipgate_flow::flow::socket::{Connection, FlowSocket, Frame, MockConnection};
//! use sipgate_flow::{FlowResponse, Event};
//! # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
//! let connection = MockConnection::new([
//!     Frame::text(r#"{"type":"user_speak","text":"Hallo","session":{"id":"s1"}}"#),
//!     Frame::Close,
//! ]);
//! let socket = FlowSocket::new(connection.clone());
//!
//! while let Some(event) = socket.next_event().await? {
//!     // Same handler code as a webhook: build the response, send it back.
//!     let response = FlowResponse::none();
//!     socket.send_response(&event, &response).await?;
//! }
//!
//! assert_eq!(socket.connection().sent(), Vec::new(), "no action, nothing sent");
//! # Ok::<(), sipgate_flow::Error>(())
//! # });
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "websocket"))]
//! # fn main() {}
//! ```
//!
//! # What the transport does not provide
//!
//! The handshake is not authenticated by any documented mechanism: the Flow
//! dashboard stores the URL and the documentation names no header, token or
//! subprotocol for the connection, so this module invents none and every
//! security check stays where the socket is accepted. `docs/contracts.md` §7.9
//! records the gap and §3.2 records what the page does document.
//!
//! Nothing here spawns a task, sleeps or owns a runtime. [`FlowSocket::run`]
//! drives **one** connection until Flow closes it; the accept loop that
//! reconnects after a dropped link is the caller's, paced by
//! [`AcceptBackoff`] and the caller-supplied [`crate::Sleeper`], exactly like
//! the HTTP client's retries.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::flow::action::Action;
use crate::flow::event::{Event, MAX_EVENT_BODY_BYTES};
use crate::flow::response::FlowResponse;
use crate::retry::{RetryPolicy, MIN_RETRY_DELAY};

/// Largest inbound frame [`FlowSocket`] accepts, in bytes.
///
/// This is the same ceiling [`crate::Event::parse`] applies
/// ([`MAX_EVENT_BODY_BYTES`]): a larger frame could never parse into an event,
/// so [`FlowSocket::with_max_message_bytes`] refuses a limit above it instead of
/// accepting a bound that cannot be enforced.
///
/// ```
/// assert_eq!(
///     sipgate_flow::MAX_SOCKET_MESSAGE_BYTES,
///     sipgate_flow::MAX_EVENT_BODY_BYTES
/// );
/// ```
pub const MAX_SOCKET_MESSAGE_BYTES: usize = MAX_EVENT_BODY_BYTES;

/// One WebSocket frame as your server sees it.
///
/// The variants mirror `WebSocket`'s own message kinds, so an adapter maps one
/// message into one variant instead of deciding what a frame means:
///
/// * `Text` and `Binary` both carry a JSON payload; [`FlowSocket::next_event`]
///   treats them identically, because a framework that hands every message over
///   as bytes must not turn a valid event into an error.
/// * `Ping` is answered with a `Pong` carrying the same payload, as
///   <https://flow.sipgate.io/api/websocket> asks ("respond with pong frames").
/// * `Pong` is ignored.
/// * `Close` ends the connection: [`FlowSocket::next_event`] reports the link as
///   finished.
///
/// ```
/// use sipgate_flow::flow::socket::Frame;
///
/// assert_eq!(Frame::text("{}").byte_len(), 2);
/// assert_eq!(Frame::Close.byte_len(), 0);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A JSON text message.
    Text(String),
    /// A message your framework delivered as bytes.
    Binary(Vec<u8>),
    /// Keep-alive probe; answer with [`Frame::Pong`].
    Ping(Vec<u8>),
    /// Answer to a [`Frame::Ping`]; carries no meaning for Flow.
    Pong(Vec<u8>),
    /// The peer closed the connection.
    Close,
}

impl Frame {
    /// A [`Frame::Text`] from anything string-like.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::Frame;
    ///
    /// assert_eq!(Frame::text("{}"), Frame::Text("{}".to_string()));
    /// ```
    #[must_use]
    pub fn text(body: impl Into<String>) -> Self {
        Self::Text(body.into())
    }

    /// Size of the payload in bytes, `0` for [`Frame::Close`].
    ///
    /// This is the number [`FlowSocket::with_max_message_bytes`] is compared
    /// against; a text frame counts its UTF-8 bytes.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::Frame;
    ///
    /// assert_eq!(Frame::Ping(vec![0, 1, 2]).byte_len(), 3);
    /// assert_eq!(Frame::text("Grüße").byte_len(), "Grüße".len());
    /// ```
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Text(body) => body.len(),
            Self::Binary(bytes) | Self::Ping(bytes) | Self::Pong(bytes) => bytes.len(),
            Self::Close => 0,
        }
    }
}

/// One live WebSocket connection, as [`FlowSocket`] needs it.
///
/// Implement it once per server framework; [`MockConnection`] is the in-memory
/// implementation this crate's tests and examples use, so no doctest here opens
/// a socket.
///
/// The contract:
///
/// * [`Connection::recv`] returns [`None`] once the peer closed, and a
///   [`Frame::Close`] is equally acceptable; either way [`FlowSocket`] reports
///   the link as finished instead of inventing an error.
/// * [`Connection::send`] writes one frame, in order. It must not interpret
///   actions.
/// * Both methods take `&self`: one connection is shared, so put the mutable
///   half behind a mutex or a split sink/stream, and never hold a lock across
///   an `.await` of the *other* call.
/// * A failure carries its cause: wrap your library's error with
///   [`Error::socket_with_source`] so the chain survives.
///
/// ```
/// use sipgate_flow::flow::socket::{Connection, Frame};
/// use sipgate_flow::Result;
///
/// struct Swallowing;
///
/// impl Connection for Swallowing {
///     async fn recv(&self) -> Result<Option<Frame>> {
///         Ok(Some(Frame::text("{}")))
///     }
///
///     async fn send(&self, _frame: Frame) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
pub trait Connection: Send + Sync {
    /// Reads the next frame, or `None` when the peer closed the connection.
    ///
    /// # Errors
    ///
    /// [`Error::Socket`] when the underlying socket failed.
    fn recv(&self) -> impl Future<Output = Result<Option<Frame>>> + Send;

    /// Writes one frame.
    ///
    /// # Errors
    ///
    /// [`Error::Socket`] when the underlying socket failed.
    fn send(&self, frame: Frame) -> impl Future<Output = Result<()>> + Send;
}

/// An in-memory [`Connection`]: replays scripted frames, records what it sent.
///
/// It is the mock this crate's tests use, and it is public so a caller can test
/// a Flow handler without a socket, a runtime or a peer. Frames pushed after
/// construction are handed out in order; once the script is empty [`recv`]
/// reports the connection as closed.
///
/// Cloning shares the same two queues, so a test keeps a probe handle after the
/// connection moved into [`FlowSocket`].
///
/// [`recv`]: Connection::recv
///
/// ```
/// # #[cfg(feature = "websocket")]
/// # fn main() -> Result<(), sipgate_flow::Error> {
/// use sipgate_flow::flow::socket::{Connection, Frame, MockConnection};
/// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
/// let connection = MockConnection::new([Frame::text("{}")]);
/// assert_eq!(connection.recv().await?, Some(Frame::text("{}")));
/// assert_eq!(connection.recv().await?, None, "an empty script means closed");
///
/// connection.send(Frame::text("{}")).await?;
/// assert_eq!(connection.sent(), vec![Frame::text("{}")]);
/// # Ok::<(), sipgate_flow::Error>(())
/// # });
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "websocket"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone, Default)]
pub struct MockConnection {
    incoming: Arc<Mutex<VecDeque<Frame>>>,
    sent: Arc<Mutex<Vec<Frame>>>,
}

impl MockConnection {
    /// A connection that replays `frames` and then reports the link as closed.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{Frame, MockConnection};
    ///
    /// let connection = MockConnection::new([Frame::text("a"), Frame::Close]);
    /// assert!(connection.sent().is_empty());
    /// ```
    #[must_use]
    pub fn new(frames: impl IntoIterator<Item = Frame>) -> Self {
        Self {
            incoming: Arc::new(Mutex::new(frames.into_iter().collect())),
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Appends a frame to the incoming script, for a test that feeds the link
    /// while the driver is already running.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{Frame, MockConnection};
    ///
    /// let connection = MockConnection::default();
    /// connection.push(Frame::text("{}"));
    /// ```
    pub fn push(&self, frame: Frame) {
        lock(&self.incoming).push_back(frame);
    }

    /// Every frame written so far, in order.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{Frame, MockConnection};
    ///
    /// let connection = MockConnection::new([Frame::text("{}")]);
    /// assert_eq!(connection.sent().len(), 0);
    /// ```
    #[must_use]
    pub fn sent(&self) -> Vec<Frame> {
        lock(&self.sent).clone()
    }
}

impl Connection for MockConnection {
    async fn recv(&self) -> Result<Option<Frame>> {
        Ok(lock(&self.incoming).pop_front())
    }

    async fn send(&self, frame: Frame) -> Result<()> {
        lock(&self.sent).push(frame);
        Ok(())
    }
}

/// Locks a mutex without unwrapping: a poisoned lock still holds a consistent
/// value here, because every critical section is a single push, pop or clone.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drives one WebSocket connection: frames in, typed events out, actions back.
///
/// One Flow call is one connection (Flow connects when the call starts and may
/// close when it ends), so this type is the per-call unit: build it in your
/// server's `on_connection` handler, then either call [`FlowSocket::run`] or
/// drive [`FlowSocket::next_event`] and [`FlowSocket::send_response`] yourself.
///
/// The event set is the one [`crate::Event`] models — including
/// `user_speech_started`, which sipgate documents as WebSocket-only — and the
/// action set is the one [`crate::Action`] models, validated on construction.
/// Outbound messages are not size-capped: a `speak` with a long text or an
/// `audio` action with a base64 WAV legitimately exceeds the inbound ceiling.
///
/// ```
/// # #[cfg(feature = "websocket")]
/// # fn main() -> Result<(), sipgate_flow::Error> {
/// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
/// use sipgate_flow::{Action, FlowResponse};
/// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
/// let connection = MockConnection::new([
///     Frame::text(r#"{"type":"dtmf_received","digit":"7","session":{"id":"s1"}}"#),
/// ]);
/// let socket = FlowSocket::new(connection);
/// let probe = socket.connection().clone();
///
/// let event = socket.next_event().await?.expect("one event");
/// let Some(session) = event.session_id() else {
///     return Ok(()); // unaddressable: nothing to answer
/// };
/// let response = FlowResponse::one(Action::speak(session, "Verbinde")?);
/// assert_eq!(socket.send_response(&event, &response).await?, 1);
/// assert_eq!(probe.sent().len(), 1);
/// # Ok::<(), sipgate_flow::Error>(())
/// # });
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "websocket"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone)]
pub struct FlowSocket<C> {
    connection: C,
    max_message_bytes: usize,
}

impl<C: Connection> FlowSocket<C> {
    /// A driver over `connection` that accepts frames up to
    /// [`MAX_SOCKET_MESSAGE_BYTES`].
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{FlowSocket, MockConnection};
    /// use sipgate_flow::MAX_SOCKET_MESSAGE_BYTES;
    ///
    /// let socket = FlowSocket::new(MockConnection::default());
    /// assert_eq!(socket.max_message_bytes(), MAX_SOCKET_MESSAGE_BYTES);
    /// ```
    #[must_use]
    pub fn new(connection: C) -> Self {
        Self {
            connection,
            max_message_bytes: MAX_SOCKET_MESSAGE_BYTES,
        }
    }

    /// The connection this driver owns.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
    ///
    /// let socket = FlowSocket::new(MockConnection::new([Frame::Close]));
    /// assert!(socket.connection().sent().is_empty());
    /// ```
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// The largest inbound frame accepted, in bytes.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{FlowSocket, MockConnection};
    ///
    /// let socket = FlowSocket::new(MockConnection::default());
    /// assert_eq!(socket.max_message_bytes(), 64 * 1024);
    /// ```
    #[must_use]
    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Tightens the inbound frame ceiling.
    ///
    /// The accepted range is `1..=MAX_SOCKET_MESSAGE_BYTES`. `0` is refused
    /// instead of turning every frame into `BodyTooLarge`, and a value above
    /// [`MAX_SOCKET_MESSAGE_BYTES`] is refused because
    /// [`crate::Event::parse`] would reject such a body anyway — the driver
    /// never promises a bound it cannot enforce.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::{FlowSocket, MockConnection};
    ///
    /// let socket = FlowSocket::new(MockConnection::default()).with_max_message_bytes(4096)?;
    /// assert_eq!(socket.max_message_bytes(), 4096);
    /// assert!(FlowSocket::new(MockConnection::default()).with_max_message_bytes(0).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] with field `max_message_bytes` when `limit` is `0`
    /// or above [`MAX_SOCKET_MESSAGE_BYTES`].
    pub fn with_max_message_bytes(mut self, limit: usize) -> Result<Self> {
        if limit == 0 {
            return Err(Error::validation(
                "max_message_bytes",
                "must be at least 1 byte",
            ));
        }
        if limit > MAX_SOCKET_MESSAGE_BYTES {
            return Err(Error::validation(
                "max_message_bytes",
                format!("must not exceed {MAX_SOCKET_MESSAGE_BYTES} bytes"),
            ));
        }
        self.max_message_bytes = limit;
        Ok(self)
    }

    /// The next event, or `None` once the link is finished.
    ///
    /// Pings are answered with a pong carrying the same payload, pongs are
    /// skipped, and a [`Frame::Close`] (or a closed [`Connection`]) reports
    /// [`None`]. Text and binary frames are parsed with [`Event::parse`], so the
    /// tolerance is the same one the webhook path has: unknown fields, unknown
    /// event types, `camelCase` and `snake_case` all arrive intact.
    ///
    /// Not intended to be called from two tasks on the same connection: the
    /// frames are a single ordered stream.
    ///
    /// ```
    /// # #[cfg(feature = "websocket")]
    /// # fn main() -> Result<(), sipgate_flow::Error> {
    /// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
    /// use sipgate_flow::EventPayload;
    /// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
    /// let connection = MockConnection::new([
    ///     Frame::Ping(b"keep-alive".to_vec()),
    ///     Frame::Binary(br#"{"type":"user_speech_started","session":{"id":"s1"}}"#.to_vec()),
    ///     Frame::Close,
    /// ]);
    /// let socket = FlowSocket::new(connection.clone());
    ///
    /// let event = socket.next_event().await?.expect("one event");
    /// assert!(matches!(event.payload(), EventPayload::UserSpeechStarted));
    /// assert_eq!(connection.sent(), vec![Frame::Pong(b"keep-alive".to_vec())]);
    /// assert!(socket.next_event().await?.is_none(), "close ends the link");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// # });
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "websocket"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Error::BodyTooLarge`] when a frame exceeds the configured ceiling.
    /// * [`Error::EmptyBody`] / [`Error::Json`] / [`Error::Validation`] from
    ///   [`Event::parse`] when the payload is not a usable event.
    /// * [`Error::Socket`] when reading a frame or answering a ping failed.
    pub async fn next_event(&self) -> Result<Option<Event>> {
        loop {
            let Some(frame) = self.connection.recv().await? else {
                return Ok(None);
            };
            match frame {
                Frame::Close => return Ok(None),
                Frame::Pong(_) => {}
                Frame::Ping(payload) => self.connection.send(Frame::Pong(payload)).await?,
                Frame::Text(body) => return self.event_from(body.as_bytes()),
                Frame::Binary(bytes) => return self.event_from(&bytes),
            }
        }
    }

    /// Sends `response` for `event`, returning how many actions were written.
    ///
    /// One action is sent as a single JSON object, several as an array in
    /// order, and an empty [`FlowResponse`] sends nothing at all — on this
    /// transport "no action" is silence, not an HTTP status. An event that
    /// accepts no action ([`Event::accepts_actions`] is `false`, for example
    /// `session_end`) makes a non-empty response a protocol error instead of a
    /// message Flow would have to discard.
    ///
    /// ```
    /// # #[cfg(feature = "websocket")]
    /// # fn main() -> Result<(), sipgate_flow::Error> {
    /// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
    /// use sipgate_flow::{Action, Error, Event, FlowResponse};
    /// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
    /// let connection = MockConnection::default();
    /// let socket = FlowSocket::new(connection.clone());
    /// let event = Event::parse(br#"{"type":"user_speak","text":"Hallo","session":{"id":"s1"}}"#)?;
    ///
    /// let none = FlowResponse::none();
    /// assert_eq!(socket.send_response(&event, &none).await?, 0);
    /// assert!(connection.sent().is_empty());
    ///
    /// let one = FlowResponse::one(Action::speak("s1", "Hallo!")?);
    /// assert_eq!(socket.send_response(&event, &one).await?, 1);
    ///
    /// let ending = Event::parse(br#"{"type":"session_end","session":{"id":"s1"}}"#)?;
    /// let refused = Action::speak("s1", "Tschüss")?;
    /// assert!(matches!(
    ///     socket.send_response(&ending, &FlowResponse::one(refused)).await,
    ///     Err(Error::ActionNotAccepted { kind }) if kind == "session_end"
    /// ));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// # });
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "websocket"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Error::ActionNotAccepted`] when the event carries no action contract
    ///   and the response is not empty.
    /// * [`Error::JsonEncode`] when an action could not be encoded.
    /// * [`Error::Socket`] when the frame could not be written.
    pub async fn send_response(&self, event: &Event, response: &FlowResponse) -> Result<usize> {
        self.deliver(event.accepts_actions(), event.kind(), response)
            .await
    }

    /// Sends one action without waiting for an event.
    ///
    /// The transport is bidirectional and both sides may start a message, so an
    /// application can speak, hang up or transfer proactively
    /// (<https://flow.sipgate.io/api/websocket>, "Unsolicited actions"). The
    /// action still addresses its session by `session_id`, exactly as in a
    /// response.
    ///
    /// ```
    /// # #[cfg(feature = "websocket")]
    /// # fn main() -> Result<(), sipgate_flow::Error> {
    /// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
    /// use sipgate_flow::Action;
    /// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
    /// let connection = MockConnection::default();
    /// let socket = FlowSocket::new(connection.clone());
    ///
    /// socket.send_action(&Action::speak("s1", "Einen Moment")?).await?;
    ///
    /// let sent = connection.sent();
    /// assert!(matches!(&sent[..], [Frame::Text(body)]
    ///     if body.contains("\"type\":\"speak\"") && body.contains("\"session_id\":\"s1\"")));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// # });
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "websocket"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Error::JsonEncode`] when the action could not be encoded.
    /// * [`Error::Socket`] when the frame could not be written.
    pub async fn send_action(&self, action: &Action) -> Result<()> {
        self.write(Frame::text(encode_action(action)?)).await
    }

    /// Drives this connection until Flow closes it, returning the events handled.
    ///
    /// `handler` receives each event **by value**, so it may be an `async`
    /// closure that talks to a database, an LLM or the REST API; the response it
    /// returns is sent with [`FlowSocket::send_response`] and the loop continues.
    /// The first error — from the socket, from the parser or from the handler —
    /// ends the loop and is returned unchanged; the frames after it stay
    /// unread, so a caller may inspect the error and call [`FlowSocket::run`]
    /// again.
    ///
    /// ```
    /// # #[cfg(feature = "websocket")]
    /// # fn main() -> Result<(), sipgate_flow::Error> {
    /// use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};
    /// use sipgate_flow::{Action, EventPayload, FlowResponse};
    /// # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
    /// let connection = MockConnection::new([
    ///     Frame::text(r#"{"type":"user_speak","text":"Hilfe","session":{"id":"s1"}}"#),
    ///     Frame::text(r#"{"type":"session_end","session":{"id":"s1"}}"#),
    ///     Frame::Close,
    /// ]);
    /// let socket = FlowSocket::new(connection.clone());
    ///
    /// let handled = socket.run(|event| async move {
    ///     let text = match event.payload() {
    ///         EventPayload::UserSpeak { text, .. } => text.clone(),
    ///         _ => String::new(),
    ///     };
    ///     // A handler that needs an await belongs exactly here.
    ///     let response = match event.session_id() {
    ///         Some(session) => FlowResponse::one(Action::speak(session, text)?),
    ///         None => FlowResponse::none(),
    ///     };
    ///     Ok(response)
    /// }).await?;
    ///
    /// assert_eq!(handled, 2, "the silent session_end was handled too");
    /// assert_eq!(connection.sent().len(), 1, "only the user_speak answered");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// # });
    /// # Ok(())
    /// # }
    /// # #[cfg(not(feature = "websocket"))]
    /// # fn main() {}
    /// ```
    ///
    /// # Errors
    ///
    /// The first error from [`FlowSocket::next_event`], from `handler`, or from
    /// [`FlowSocket::send_response`].
    pub async fn run<F, Fut>(&self, mut handler: F) -> Result<usize>
    where
        F: FnMut(Event) -> Fut,
        Fut: Future<Output = Result<FlowResponse>>,
    {
        let mut count = 0_usize;
        while let Some(event) = self.next_event().await? {
            let accepts = event.accepts_actions();
            let kind = event.kind().to_string();
            let response = handler(event).await?;
            self.deliver(accepts, &kind, &response).await?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    /// Parses one payload, applying the configured ceiling before the parser
    /// looks at it.
    fn event_from(&self, body: &[u8]) -> Result<Option<Event>> {
        if body.len() > self.max_message_bytes {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: self.max_message_bytes,
            });
        }
        Event::parse(body).map(Some)
    }

    /// The action contract shared by [`FlowSocket::run`] and
    /// [`FlowSocket::send_response`].
    ///
    /// One message per response, not one per action: a webhook body and the
    /// SDK's WebSocket send both put the whole response in one frame, so an
    /// array of actions stays ordered inside a single message.
    async fn deliver(
        &self,
        accepts_actions: bool,
        kind: &str,
        response: &FlowResponse,
    ) -> Result<usize> {
        // The same three shapes the webhook body has: nothing, one object, or
        // an array. `actions()` is the single source, so a `Many` built with no
        // actions degrades to silence exactly like `[]` does over HTTP.
        let body = match response.actions() {
            [] => return Ok(0),
            [action] => encode_action(action)?,
            actions => serde_json::to_string(&serde_json::Value::Array(
                actions.iter().map(Action::to_json).collect(),
            ))
            .map_err(Error::json_encode)?,
        };
        if !accepts_actions {
            return Err(Error::ActionNotAccepted {
                kind: kind.to_string(),
            });
        }
        self.write(Frame::text(body)).await?;
        Ok(response.len())
    }

    /// Writes one already-encoded frame.
    async fn write(&self, frame: Frame) -> Result<()> {
        self.connection.send(frame).await
    }
}

/// One action as the wire message: the same flat object a webhook body carries.
///
/// A `Value` built from strings, numbers and arrays always serialises; the
/// failure surface is kept because this crate never turns an encoding problem
/// into a panic.
fn encode_action(action: &Action) -> Result<String> {
    serde_json::to_string(&action.to_json()).map_err(Error::json_encode)
}

/// Paces a reconnecting accept loop: the delay after `failures` dropped links.
///
/// Flow is the connector, so "reconnect" on this side means "accept again": when
/// a connection cannot be established or a handler fails, the server keeps
/// listening, and this type answers how long to wait before the next accept.
/// Unlike [`RetryPolicy::delay`] it never runs out of budget — an endpoint that
/// stopped accepting would silently stop answering calls — so once the policy's
/// attempts are spent the ceiling [`RetryPolicy::max_delay`] is returned and the
/// loop keeps retrying. Every value is jittered and clamped to
/// `MIN_RETRY_DELAY..=RetryPolicy::max_delay`, so a burst of failures cannot
/// become a busy loop.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::flow::socket::AcceptBackoff;
/// use sipgate_flow::{RetryPolicy, MIN_RETRY_DELAY};
///
/// let backoff = AcceptBackoff::new(RetryPolicy::new(4).with_max_delay(Duration::from_secs(2)));
///
/// // Inside the budget: a jittered step, never zero.
/// let step = backoff.delay(3);
/// assert!(step >= MIN_RETRY_DELAY && step <= Duration::from_secs(2));
///
/// // Budget spent: the ceiling, forever, instead of giving up.
/// assert_eq!(backoff.delay(4), Duration::from_secs(2));
/// assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(2));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptBackoff {
    policy: RetryPolicy,
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new(RetryPolicy::default().with_base_delay(Duration::from_secs(1)))
    }
}

impl AcceptBackoff {
    /// Wraps any retry policy as an endless accept pacing.
    ///
    /// ```
    /// use sipgate_flow::flow::socket::AcceptBackoff;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let backoff = AcceptBackoff::new(RetryPolicy::none());
    /// assert_eq!(backoff.policy().max_attempts, 1);
    /// ```
    #[must_use]
    pub fn new(policy: RetryPolicy) -> Self {
        Self { policy }
    }

    /// The policy whose base delay, ceiling and jitter are used.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::flow::socket::AcceptBackoff;
    /// use sipgate_flow::RetryPolicy;
    ///
    /// let backoff = AcceptBackoff::new(RetryPolicy::default().with_max_delay(Duration::from_secs(4)));
    /// assert_eq!(backoff.policy().max_delay, Duration::from_secs(4));
    /// ```
    #[must_use]
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// How long to wait after `failures` consecutive failures.
    ///
    /// `0` behaves like `1` (the first failure just happened). The result is
    /// never below [`MIN_RETRY_DELAY`] and never above
    /// [`RetryPolicy::max_delay`], even when a `RetryPolicy` was built with its
    /// public fields instead of the builders and carries an impossible ceiling.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::flow::socket::AcceptBackoff;
    /// use sipgate_flow::{RetryPolicy, MIN_RETRY_DELAY};
    ///
    /// let backoff = AcceptBackoff::new(RetryPolicy::default());
    /// // `0` is the first failure, so it yields the first jittered step
    /// // (`[base/2, base]`), never a free pass.
    /// let first = Duration::from_millis(250);
    /// assert!(backoff.delay(0) >= first / 2 && backoff.delay(0) <= first);
    /// assert!(backoff.delay(1) >= first / 2 && backoff.delay(1) <= first);
    /// assert!(backoff.delay(1) >= MIN_RETRY_DELAY);
    /// ```
    #[must_use]
    pub fn delay(&self, failures: u32) -> Duration {
        self.policy
            .delay(failures.max(1), None)
            .unwrap_or(self.policy.max_delay)
            .max(MIN_RETRY_DELAY)
    }
}
