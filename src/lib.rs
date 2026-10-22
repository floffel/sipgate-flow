//! Typed client for sipgate's voice-flow API.
//!
//! The API is only partially documented, so this crate is deliberately
//! **tolerant**: unknown events and unknown fields never fail parsing, they
//! surface as [`Event::Unknown`] so a bot can log and ignore them.
//!
//! ```
//! use sipgate_flow::{Event, Action};
//!
//! let event = Event::parse(br#"{"event":"answered","callId":"abc"}"#)?;
//! assert!(matches!(event, Event::Answered { .. }));
//!
//! let action = Action::say("Willkommen!");
//! assert_eq!(action.kind(), "tts");
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod action;
pub mod client;
pub mod error;
pub mod event;

pub use action::Action;
pub use client::SipgateFlowClient;
pub use error::{Error, Result};
pub use event::Event;
