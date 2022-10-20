use std::net::Ipv6Addr;

use super::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Vendor defined options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LqClientLink {
    pub link_addresses: Vec<Ipv6Addr>,
}

impl Decodable for LqClientLink {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut link_addresses = Vec::with_capacity(len / 16);
        for _ in 0..(len / 16) {
            link_addresses.push(decoder.read::<16>()?.into());
        }

        Ok(LqClientLink { link_addresses })
    }
}

impl Encodable for LqClientLink {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::LqClientLink.into())?;
        e.write_u16(self.link_addresses.len() as u16 * 16)?;
        for address in self.link_addresses.iter() {
            e.write_slice(&address.octets())?;
        }

        Ok(())
    }
}
