use super::{DecodeResult, Duid, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Server Identity
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerId {
    pub id: Duid,
}

impl Decodable for ServerId {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);
        Ok(ServerId {
            id: Duid::decode(&mut decoder)?,
        })
    }
}

impl Encodable for ServerId {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.id.encode(&mut opt_enc)?;
        e.write_u16(OptionCode::ServerId.into())?;
        e.write_u16(buf.len() as u16)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_server_id_encode_decode() {
        let option = ServerId {
            id: Duid::enterprise(1, &[1, 2, 3]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = ServerId::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = ServerId::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
