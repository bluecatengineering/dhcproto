use crate::v6::DhcpOption;
use crate::v6::{DecodeResult, EncodeResult, Ipv6Addr, OptionCode, StatusCode, option_builder};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association Address
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAAddr {
    pub addr: Ipv6Addr,
    pub preferred_life: u32,
    pub valid_life: u32,
    // 24 + opts.len()
    // should this be DhcpOptions ?
    // the RFC suggests it 'encapsulates options'
    pub opts: IAAddrOptions,
}

impl Decodable for IAAddr {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
		decoder.read::<2>()?;
		let len = decoder.read_u16()? as usize;
		let mut decoder = Decoder::new(decoder.read_slice(len)?);
        Ok(IAAddr {
            addr: decoder.read::<16>()?.into(),
            preferred_life: decoder.read_u32()?,
            valid_life: decoder.read_u32()?,
            opts: IAAddrOptions::decode(&mut decoder)?,
        })
    }
}

impl Encodable for IAAddr {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        // write len
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;
		e.write_u16(OptionCode::IAAddr.into())?;
        // buf now has total len
        e.write_u16(24 + buf.len() as u16)?;
        // data
        e.write_u128((self.addr).into())?;
        e.write_u32(self.preferred_life)?;
        e.write_u32(self.valid_life)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}

option_builder!(IAAddrOption, IAAddrOptions, DhcpOption, StatusCode);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iaaddr_encode_decode() {
        let option = IAAddr {
            addr: "FE:80::AB".parse().unwrap(),
            preferred_life: 0xEF12,
            valid_life: 0xABCD,
            opts: IAAddrOptions(vec![StatusCode {
                status: 0xABCDu16.into(),
                msg: "message".into(),
            }
            .into()]),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = IAAddr::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = IAAddr::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
