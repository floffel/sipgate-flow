//! What a webhook handler returns: no action, one action, or a sequence.
//!
//! The HTTP contract is `200` with a JSON object or array, or `204` with no
//! body — the latter also covers `200` with `{}` or `[]`, which the service
//! treats the same way. This type renders the canonical form and refuses to
//! build an empty array, so a handler cannot accidentally send `[]` where it
//! meant `204`.
//!
//! ```
//! use sipgate_flow::{Action, FlowResponse};
//!
//! let response = FlowResponse::many([Action::barge_in("s1")?, Action::speak("s1", "Neu")?]);
//! assert_eq!(response.status(), 200);
//! assert!(response.body().unwrap().starts_with('['));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use serde_json::Value;

use crate::flow::action::Action;

/// The body a webhook handler answers with.
///
/// ```
/// use sipgate_flow::FlowResponse;
///
/// let response = FlowResponse::none();
/// assert_eq!(response.status(), 204);
/// assert!(response.body().is_none());
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FlowResponse {
    /// `204 No Content`: nothing to do for this event.
    NoContent,
    /// `200 OK` with a single action object.
    One(Action),
    /// `200 OK` with an array, executed in order.
    Many(Vec<Action>),
}

impl FlowResponse {
    /// No action for this event.
    ///
    /// ```
    /// use sipgate_flow::FlowResponse;
    /// assert!(FlowResponse::none().is_no_content());
    /// ```
    #[must_use]
    pub fn none() -> Self {
        Self::NoContent
    }

    /// A single action.
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// let response = FlowResponse::one(Action::hangup("s1")?);
    /// assert_eq!(response.status(), 200);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn one(action: Action) -> Self {
        Self::One(action)
    }

    /// A sequence, executed in order. An empty iterator collapses to
    /// [`FlowResponse::NoContent`].
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// let two = FlowResponse::many([Action::barge_in("s1")?, Action::hangup("s1")?]);
    /// assert_eq!(two.len(), 2);
    /// let none = FlowResponse::many(std::iter::empty::<Action>());
    /// assert!(none.is_no_content());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn many(actions: impl IntoIterator<Item = Action>) -> Self {
        let mut actions = actions.into_iter().collect::<Vec<_>>();
        match actions.len() {
            0 => Self::NoContent,
            // A one-element array is legal, but an object is the simpler shape
            // and both mean the same thing to the service.
            1 => actions.pop().map_or(Self::NoContent, Self::One),
            _ => Self::Many(actions),
        }
    }

    /// The HTTP status a framework should send.
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// assert_eq!(FlowResponse::none().status(), 204);
    /// assert_eq!(FlowResponse::one(Action::barge_in("s")?).status(), 200);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NoContent => 204,
            Self::One(_) | Self::Many(_) => 200,
        }
    }

    /// The JSON value to send, or `None` for `204`.
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// let response = FlowResponse::one(Action::hangup("s1")?);
    /// assert_eq!(
    ///     response.to_json().unwrap(),
    ///     serde_json::json!({"type": "hangup", "session_id": "s1"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Option<Value> {
        match self {
            Self::NoContent => None,
            Self::One(action) => Some(action.to_json()),
            Self::Many(actions) => {
                Some(Value::Array(actions.iter().map(Action::to_json).collect()))
            }
        }
    }

    /// The serialised body, or `None` for `204`.
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// let response = FlowResponse::one(Action::hangup("s1")?);
    /// assert_eq!(
    ///     response.body().unwrap(),
    ///     r#"{"session_id":"s1","type":"hangup"}"#
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn body(&self) -> Option<String> {
        // A `Value` built from strings, numbers and arrays always serialises;
        // an impossible failure degrades to "no body", never to a panic.
        self.to_json()
            .and_then(|value| serde_json::to_string(&value).ok())
    }

    /// Whether this response carries no body.
    ///
    /// ```
    /// use sipgate_flow::FlowResponse;
    /// assert!(FlowResponse::none().is_no_content());
    /// ```
    #[must_use]
    pub fn is_no_content(&self) -> bool {
        matches!(self, Self::NoContent)
    }

    /// The actions, in order (empty for `204`).
    ///
    /// ```
    /// use sipgate_flow::{Action, FlowResponse};
    ///
    /// let response = FlowResponse::one(Action::hangup("s1")?);
    /// assert_eq!(response.actions().len(), 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        match self {
            Self::NoContent => &[],
            Self::One(action) => std::slice::from_ref(action),
            Self::Many(actions) => actions,
        }
    }

    /// How many actions the response carries.
    ///
    /// ```
    /// use sipgate_flow::FlowResponse;
    /// assert_eq!(FlowResponse::none().len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.actions().len()
    }

    /// Whether the response carries no action. Mirrors
    /// [`FlowResponse::len`] for lint-clean call sites.
    ///
    /// ```
    /// use sipgate_flow::FlowResponse;
    /// assert!(FlowResponse::none().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Action> for FlowResponse {
    fn from(action: Action) -> Self {
        Self::One(action)
    }
}
