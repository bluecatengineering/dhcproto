use std::fmt;

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

/// Represents available flags on message
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Flags(u16);

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flags")
            .field("broadcast", &self.broadcast())
            .finish()
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Flags {
    /// Create new Flags from u16
    pub fn new(n: u16) -> Self {
        Flags(n)
    }
    /// get the status of the broadcast flag
    pub fn broadcast(&self) -> bool {
        (self.0 & 0x80_00) >> 15 == 1
    }
}

impl From<u16> for Flags {
    fn from(n: u16) -> Self {
        Flags(n)
    }
}
impl From<Flags> for u16 {
    fn from(f: Flags) -> Self {
        f.0
    }
}

impl Decodable for Flags {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(decoder.read_u16()?.into())
    }
}

impl Encodable for Flags {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16((*self).into())
    }
}
