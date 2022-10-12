use super::{DecodeResult, EncodeResult, Ipv6Addr, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Unicast {
    pub server_address: Ipv6Addr,
}

impl Decodable for Unicast {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let _len = decoder.read_u16()? as usize;
        Ok(Unicast {
            server_address: decoder.read::<16>()?.into(),
        })
    }
}

impl Encodable for Unicast {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::Unicast.into())?;
        e.write_u16(16)?;
        e.write_u128(self.server_address.into())?;
        Ok(())
    }
}

//impl From<Unicast> for Message?

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_server_id_encode_decode() {
        let option = Unicast {
            server_address: "FE80::".parse().unwrap(),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = Unicast::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = Unicast::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
