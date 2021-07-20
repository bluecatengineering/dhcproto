//! Error types for Encoding/Decoding
use thiserror::Error;

/// Convenience type for decode errors
pub type DecodeResult<T> = Result<T, DecodeError>;

/// Returned from types that decode
#[derive(Error, Clone, Debug)]
pub enum DecodeError {
    /// encountered end of buffer
    #[error("decoder ran out of bytes to read on byte {index}")]
    EndOfBuffer {
        /// index in buffer
        index: usize,
    },

    /// add overflow
    #[error("decoder checked_add failed")]
    AddOverflow,

    /// ran out of bytes
    #[error("parser ran out of data-- not enough bytes")]
    NotEnoughBytes,

    /// error converting from slice
    #[error("error converting from slice")]
    SliceError(#[from] std::array::TryFromSliceError),

    /// error finding nul in string
    #[error("error getting null terminated string")]
    NulError(#[from] std::ffi::FromBytesWithNulError),

    /// error converting to utf-8
    #[error("error converting to UTF-8")]
    Utf8Error(#[from] std::str::Utf8Error),
}

/// Returned from types that encode
#[derive(Error, Copy, Clone, Debug)]
pub enum EncodeError {
    /// addition overflow
    #[error("encoder checked_add failed")]
    AddOverflow,

    /// string exceeds bounds
    #[error(
        "message is trying to write a string to the message that exceeds the max size of {len}"
    )]
    StringSizeTooBig {
        /// size of string
        len: usize,
    },
}

/// Convenience type for encode errors
pub type EncodeResult<T> = Result<T, EncodeError>;
