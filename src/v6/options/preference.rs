use super::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preference {
    pub pref: u8,
}

impl Decodable for Preference {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let _len = decoder.read_u16()? as usize;
        Ok(Preference {
            pref: decoder.read_u8()?,
        })
    }
}

impl Encodable for Preference {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::Preference.into())?;
        e.write_u16(1)?;
        e.write_u8(self.pref)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_preference_encode_decode() {
        let option = Preference { pref: 1 };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = Preference::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = Preference::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
