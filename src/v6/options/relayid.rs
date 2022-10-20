use super::{DecodeResult, Duid, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Client Identity
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayId {
    pub id: Duid,
}

impl Decodable for RelayId {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);
        Ok(RelayId {
            id: Duid::decode(&mut decoder)?,
        })
    }
}

impl Encodable for RelayId {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.id.encode(&mut opt_enc)?;
        e.write_u16(OptionCode::RelayId.into())?;
        e.write_u16(buf.len() as u16)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}
