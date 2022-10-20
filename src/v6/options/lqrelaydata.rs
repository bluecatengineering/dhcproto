use std::net::Ipv6Addr;

use super::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Vendor defined options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LqRelayData {
    pub peer_address: Ipv6Addr,
    pub relay_message: Vec<u8>,
}

impl Decodable for LqRelayData {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);

        Ok(LqRelayData {
            peer_address: decoder.read::<16>()?.into(),
            relay_message: decoder.read_slice(len - 16)?.into(),
        })
    }
}

impl Encodable for LqRelayData {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::LqRelayData.into())?;
        e.write_u16(self.relay_message.len() as u16 + 16)?;
        e.write_slice(&self.peer_address.octets())?;
        e.write_slice(&self.relay_message)?;
        Ok(())
    }
}
