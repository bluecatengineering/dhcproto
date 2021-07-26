use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

/// Opcode of Message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// BootRequest - https://datatracker.ietf.org/doc/html/rfc1534#section-2
    BootRequest,
    /// BootReply - https://datatracker.ietf.org/doc/html/rfc1534#section-2
    BootReply,
    /// Unknown or not yet implemented
    Unknown(u8),
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
        match opcode {
            1 => Opcode::BootRequest,
            2 => Opcode::BootReply,
            _ => Opcode::Unknown(opcode),
        }
    }
}
impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        match opcode {
            Opcode::BootRequest => 1,
            Opcode::BootReply => 2,
            Opcode::Unknown(opcode) => opcode,
        }
    }
}
