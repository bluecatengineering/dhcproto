use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Opcode of Message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Opcode(pub u8);

#[allow(non_upper_case_globals)]
impl Opcode {
    /// BootRequest - <https://datatracker.ietf.org/doc/html/rfc1534#section-2>
    pub const BootRequest: Self = Self(1);
    /// BootReply - <https://datatracker.ietf.org/doc/html/rfc1534#section-2>
    pub const BootReply: Self = Self(2);
}

impl Decodable for Opcode {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(decoder.read_u8()?.into())
    }
}

impl Encodable for Opcode {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u8((*self).into())
    }
}

impl From<u8> for Opcode {
    fn from(opcode: u8) -> Self {
        Self(opcode)
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode.0
    }
}
