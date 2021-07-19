use thiserror::Error;

/// Convenience type for decode errors
pub type DecodeResult<T> = Result<T, DecodeError>;

/// Returned from types that decode
#[derive(Error, Clone, Debug)]
pub enum DecodeError {
    #[error("decoder ran out of bytes to read on byte {index}")]
    EndOfBuffer { index: usize },

    #[error("decoder checked_add failed")]
    AddOverflow,

    #[error("parser ran out of data-- not enough bytes")]
    NotEnoughBytes,

    #[error("error converting from slice")]
    SliceError(#[from] std::array::TryFromSliceError),

    #[error("error getting null terminated string")]
    NulError(#[from] std::ffi::FromBytesWithNulError),

    #[error("error converting to UTF-8")]
    Utf8Error(#[from] std::str::Utf8Error),
}

/// Returned from types that encode
#[derive(Error, Copy, Clone, Debug)]
pub enum EncodeError {
    #[error("encoder checked_add failed")]
    AddOverflow,

    #[error(
        "message is trying to write a string to the message that exceeds the max size of {len}"
    )]
    StringSizeTooBig { len: usize },
}

/// Convenience type for encode errors
pub type EncodeResult<T> = Result<T, EncodeError>;
