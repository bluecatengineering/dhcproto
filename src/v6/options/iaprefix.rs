use super::{option_builder, DecodeResult, DhcpOption, EncodeResult, Ipv6Addr, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association Prefix Delegation Prefix Option
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAPrefix {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub prefix_ip: Ipv6Addr,
    // 25 + opts.len()
    pub opts: IAPrefixOptions,
}

impl Decodable for IAPrefix {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        Ok(IAPrefix {
            preferred_lifetime: decoder.read_u32()?,
            valid_lifetime: decoder.read_u32()?,
            prefix_len: decoder.read_u8()?,
            prefix_ip: decoder.read::<16>()?.into(),
            opts: {
                let mut dec = Decoder::new(decoder.read_slice(len - 25)?);
                IAPrefixOptions::decode(&mut dec)?
            },
        })
    }
}

impl Encodable for IAPrefix {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::IAPrefix.into())?;
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;
        // buf now has total len
        e.write_u16(25 + buf.len() as u16)?;
        // write data
        e.write_u32(self.preferred_lifetime)?;
        e.write_u32(self.valid_lifetime)?;
        e.write_u8(self.prefix_len)?;
        e.write_u128(self.prefix_ip.into())?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

option_builder!(
    IAPrefixOption,
    IAPrefixOptions,
    IsIAPrefixOption,
    DhcpOption,
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iapd_encode_decode() {
        let option = IAPrefix {
            preferred_lifetime: 0,
            valid_lifetime: 0,
            prefix_len: 0,
            prefix_ip: "FE80::".parse().unwrap(),
            // 12 + opts.len()
            opts: IAPrefixOptions(vec![]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = IAPrefix::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = IAPrefix::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
