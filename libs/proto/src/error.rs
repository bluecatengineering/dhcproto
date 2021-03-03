use std::fmt;
use thiserror::Error;

/// An alias for results returned by functions of this crate
pub type ProtoResult<T> = ::std::result::Result<T, ProtoError>;

#[derive(Error, Clone, Debug)]
pub struct ProtoError {
    kind: ProtoErrorKind,
}

/// The error kind for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
pub enum ProtoErrorKind {
    /// An error with an arbitrary message
    #[error("{0}")]
    Message(String),

    /// An error with an arbitrary message
    #[error("{0}")]
    Msg(&'static str),
}

impl From<String> for ProtoError {
    fn from(msg: String) -> ProtoError {
        ProtoErrorKind::Message(msg).into()
    }
}

impl From<&'static str> for ProtoError {
    fn from(msg: &'static str) -> ProtoError {
        ProtoErrorKind::Msg(msg).into()
    }
}

impl From<ProtoErrorKind> for ProtoError {
    fn from(kind: ProtoErrorKind) -> ProtoError {
        ProtoError { kind }
    }
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}
