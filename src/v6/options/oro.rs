use super::{DecodeResult, EncodeResult, OROCode, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Option Request Option
/// <https://datatracker.ietf.org/doc/html/rfc8415#section-21.7>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ORO {
    pub opts: Vec<OROCode>,
}

impl Decodable for ORO {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read_u16()?;
        let len = decoder.read_u16()? as usize;
        Ok(ORO {
            opts: {
                decoder
                    .read_slice(len)?
                    .chunks_exact(2)
                    // TODO: use .array_chunks::<2>() when stable
                    .map(|code| OROCode::from(u16::from_be_bytes([code[0], code[1]])))
                    .collect()
            },
        })
    }
}

impl Encodable for ORO {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::ORO.into())?;
        // write len
        e.write_u16(2 * self.opts.len() as u16)?;
        // data
        for &code in self.opts.iter() {
            e.write_u16(code.into())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iata_encode_decode() {
        let option = ORO {
            opts: vec![OROCode::SolMaxRt],
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = ORO::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = ORO::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
