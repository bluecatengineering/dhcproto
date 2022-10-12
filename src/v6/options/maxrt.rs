use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SolMaxRt {
    pub value: u32,
}

impl Decodable for SolMaxRt {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;
        Ok(SolMaxRt {
            value: decoder.read_u32()?,
        })
    }
}

impl Encodable for SolMaxRt {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::SolMaxRt.into())?;
        e.write_u16(4)?;
        e.write_u32(self.value)?;
        Ok(())
    }
}

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InfMaxRt {
    pub value: u32,
}

impl Decodable for InfMaxRt {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;
        Ok(InfMaxRt {
            value: decoder.read_u32()?,
        })
    }
}

impl Encodable for InfMaxRt {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::InfMaxRt.into())?;
        e.write_u16(4)?;
        e.write_u32(self.value)?;
        Ok(())
    }
}
