use super::{DecodeResult, EncodeResult, Ipv6Addr, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LinkAddress {
    pub link_address: Ipv6Addr,
}

impl Decodable for LinkAddress {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let _len = decoder.read_u16()? as usize;
        Ok(LinkAddress {
            link_address: decoder.read::<16>()?.into(),
        })
    }
}

impl Encodable for LinkAddress {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::LinkAddress.into())?;
        e.write_u16(16)?;
        e.write_u128(self.link_address.into())?;
        Ok(())
    }
}
