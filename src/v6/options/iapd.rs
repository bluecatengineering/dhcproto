use super::{
    option_builder, DecodeResult, DhcpOption, EncodeResult, IAPrefix, OptionCode, StatusCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association Prefix Delegation
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAPD {
    pub id: u32,
    pub t1: u32,
    pub t2: u32,
    // 12 + opts.len()
    pub opts: IAPDOptions,
}

impl Decodable for IAPD {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        Ok(IAPD {
            id: decoder.read_u32()?,
            t1: decoder.read_u32()?,
            t2: decoder.read_u32()?,
            opts: {
                let mut dec = Decoder::new(decoder.read_slice(len - 12)?);
                IAPDOptions::decode(&mut dec)?
            },
        })
    }
}

impl Encodable for IAPD {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::IAPD.into())?;
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;
        // buf now has total len
        e.write_u16(12 + buf.len() as u16)?;
        // write data
        e.write_u32(self.id)?;
        e.write_u32(self.t1)?;
        e.write_u32(self.t2)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

option_builder!(
    IAPDOption,
    IAPDOptions,
    IsIAPDOption,
    DhcpOption,
    IAPrefix,
    StatusCode
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iapd_encode_decode() {
        let option = IAPD {
            id: 0xAABB,
            t1: 0xCCDDEEFF,
            t2: 0x11223344,
            // 12 + opts.len()
            opts: IAPDOptions(vec![StatusCode {
                status: 0xABCDu16.into(),
                msg: "message".into(),
            }
            .into()]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = IAPD::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = IAPD::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
