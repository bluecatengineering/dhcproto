use std::fmt;

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents available flags on message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
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
        Self(n)
    }
    /// get the status of the broadcast flag
    pub fn broadcast(&self) -> bool {
        (self.0 & 0x80_00) >> (u16::BITS - 1) == 1
    }
    /// set the broadcast bit, returns a new Flags
    pub fn set_broadcast(mut self) -> Self {
        self.0 |= 0x80_00;
        self
    }
}

impl From<u16> for Flags {
    fn from(n: u16) -> Self {
        Self(n)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast() {
        let flag = Flags::default();
        assert_eq!(flag.0, 0);
        let flag = flag.set_broadcast();
        assert_eq!(flag.0, 0x80_00);
        assert!(flag.broadcast());

        let flag = Flags::new(0x00_20).set_broadcast();
        assert_eq!(flag.0, 0x80_20);
    }
}
