use super::{
    option_builder, DecodeResult, DhcpOption, EncodeResult, IAAddr, OptionCode, StatusCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IATA {
    pub id: u32,
    // 4 + opts.len()
    pub opts: IATAOptions,
}

impl Decodable for IATA {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
		decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);
        Ok(IATA {
            id: decoder.read_u32()?,
            opts: IATAOptions::decode(&mut decoder)?,
        })
    }
}

impl Encodable for IATA {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;
        // buf now has total len
        e.write_u16(OptionCode::IATA.into())?;
        e.write_u16(4 + buf.len() as u16)?;
        // write data
        e.write_u32(self.id)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

option_builder!(IATAOption, IATAOptions, DhcpOption, IAAddr, StatusCode);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iata_encode_decode() {
        let option = IATA {
			id: 0,
            // 12 + opts.len()
            opts: IATAOptions(vec![StatusCode {
                status: 0xABCDu16.into(),
                msg: "message".into(),
            }
            .into()]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = IATA::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = IATA::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
