use std::fmt;
use thiserror::Error;

/// An alias for results returned by functions of this crate
pub type DecodeResult<T> = ::std::result::Result<T, DecodeError>;

//#[derive(Error, Clone, Debug)]
//pub struct ProtoError {
//    kind: ProtoErrorKind,
//}

/// The error kind for errors that get returned in the crate
#[derive(Error, Clone, Debug)]
pub enum DecodeError {
    #[error("decoder ran out of bytes to read on byte {index}")]
    EndOfBuffer { index: usize },

    /// An error with an arbitrary message
    #[error("{0}")]
    Message(String),

    /// An error with an arbitrary message
    #[error("{0}")]
    Msg(&'static str),

    #[error("error converting from slice")]
    SliceError(#[from] std::array::TryFromSliceError),
}

impl From<String> for DecodeError {
    fn from(msg: String) -> DecodeError {
        Self::Message(msg)
    }
}

impl From<&'static str> for DecodeError {
    fn from(msg: &'static str) -> DecodeError {
        Self::Msg(msg)
    }
}
