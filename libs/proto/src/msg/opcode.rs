use crate::{
    decoder::{Decodable, Decoder},
    error::DecodeResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl<'r> Decodable<'r> for Opcode {
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(decoder.read_u8()?.into())
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
