use super::{
    option_builder, DecodeResult, DhcpOption, EncodeResult, IAAddr, OptionCode, StatusCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IANA {
    pub id: u32,
    pub t1: u32,
    pub t2: u32,
    // 12 + opts.len()
    pub opts: IANAOptions,
}

impl Decodable for IANA {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);
        Ok(IANA {
            id: decoder.read_u32()?,
            t1: decoder.read_u32()?,
            t2: decoder.read_u32()?,
            opts: IANAOptions::decode(&mut decoder)?,
        })
    }
}

impl Encodable for IANA {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;
        // buf now has total len
        e.write_u16(OptionCode::IANA.into())?;
        e.write_u16(12 + buf.len() as u16)?;
        // write data
        e.write_u32(self.id)?;
        e.write_u32(self.t1)?;
        e.write_u32(self.t2)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

option_builder!(IANAOption, IANAOptions, DhcpOption, IAAddr, StatusCode);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iana_encode_decode() {
        let option = IANA {
            id: 0xAABB,
            t1: 0xCCDDEEFF,
            t2: 0x11223344,
            // 12 + opts.len()
            opts: IANAOptions(vec![StatusCode {
                status: 0xABCDu16.into(),
                msg: "message".into(),
            }
            .into()]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = IANA::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = IANA::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
