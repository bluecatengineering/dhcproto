use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ElapsedTime {
    pub time: u16,
}

impl Decodable for ElapsedTime {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let _len = decoder.read_u16()? as usize;
        Ok(ElapsedTime {
            time: decoder.read_u16()?,
        })
    }
}

impl Encodable for ElapsedTime {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::ElapsedTime.into())?;
        e.write_u16(2)?;
        e.write_u16(self.time)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_server_id_encode_decode() {
        let option = ElapsedTime {
            time: 1,
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = ElapsedTime::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = ElapsedTime::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
