use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOptions {}

impl<'r> Decodable<'r> for DhcpOptions {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        todo!()
    }
}

impl<'a> Encodable<'a> for DhcpOptions {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<usize> {
        todo!()
    }
}
