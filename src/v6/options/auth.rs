use super::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Auth
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Auth {
    pub proto: u8,
    pub algo: u8,
    pub rdm: u8,
    pub replay_detection: u64,
    // 11 + len
    pub info: Vec<u8>,
}

impl Decodable for Auth {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        Ok(Auth {
            proto: decoder.read_u8()?,
            algo: decoder.read_u8()?,
            rdm: decoder.read_u8()?,
            replay_detection: decoder.read_u64()?,
            info: decoder.read_slice(len - 11)?.to_vec(),
        })
    }
}

impl Encodable for Auth {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::Auth.into())?;
        e.write_u16(11 + self.info.len() as u16)?;
        e.write_u8(self.proto)?;
        e.write_u8(self.algo)?;
        e.write_u8(self.rdm)?;
        e.write_u64(self.replay_detection)?;
        e.write_slice(&self.info)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iata_encode_decode() {
        let option = Auth {
            proto: 0xC,
            algo: 0xB,
            rdm: 0xA,
            replay_detection: 0xABCD,
            info: vec![1, 2, 3],
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = Auth::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = Auth::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
