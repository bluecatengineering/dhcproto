use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    pub fn new(n: u16) -> Self {
        Flags(n)
    }
    /// get the status of the broadcast flag
    pub fn broadcast(&self) -> bool {
        (self.0 & 0x8000) >> 15 == 1
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

impl<'r> Decodable<'r> for Flags {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(decoder.read_u16()?.into())
    }
}

impl<'a> Encodable<'a> for Flags {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<()> {
        e.write_u16((*self).into())
    }
}
