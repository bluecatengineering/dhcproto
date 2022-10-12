use super::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InformationRefreshTime {
    pub value: u32,
}

impl Decodable for InformationRefreshTime {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;
        Ok(InformationRefreshTime {
            value: decoder.read_u32()?,
        })
    }
}

impl Encodable for InformationRefreshTime {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::InformationRefreshTime.into())?;
        e.write_u16(4)?;
        e.write_u32(self.value)?;
        Ok(())
    }
}
