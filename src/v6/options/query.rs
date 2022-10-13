use std::net::Ipv6Addr;

use super::{
    option_builder, ClientId, DecodeResult, DhcpOption, EncodeResult, IAAddr, OptionCode, ORO,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Lease Query
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LqQuery {
    pub qtype: QueryType,
    pub link_address: Ipv6Addr,
    pub opts: LqQueryOptions,
}

impl Decodable for LqQuery {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        let mut decoder = Decoder::new(decoder.read_slice(len)?);
        let qtype = decoder.read_u8()?.into();
        let link_address = decoder.read::<16>()?.into();
        let opts = LqQueryOptions::decode(&mut decoder)?;
        Ok(LqQuery {
            qtype,
            link_address,
            opts,
        })
    }
}

impl Encodable for LqQuery {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        let mut buf = Vec::new();
        let mut opt_enc = Encoder::new(&mut buf);
        self.opts.encode(&mut opt_enc)?;

        e.write_u16(OptionCode::LqQuery.into())?;
        e.write_u16(buf.len() as u16 + 17)?;
        e.write_u8(self.qtype.into())?;
        e.write::<16>(self.link_address.octets())?;
        e.write_slice(&buf)?;

        Ok(())
    }
}

option_builder!(
    LqQueryOption,
    LqQueryOptions,
    DhcpOption,
    IAAddr,
    ClientId,
    ORO
);

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QueryType {
    QueryByAddress,
    QueryByClientID,
    Unknown(u8),
}

impl From<u8> for QueryType {
    fn from(qtype: u8) -> Self {
        use QueryType::*;
        match qtype {
            1 => QueryByAddress,
            2 => QueryByClientID,
            t => Unknown(t),
        }
    }
}

impl From<QueryType> for u8 {
    fn from(num: QueryType) -> Self {
        use QueryType::*;
        match num {
            QueryByAddress => 1,
            QueryByClientID => 2,
            Unknown(t) => t,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_query_option_encode_decode() {
        let option = LqQuery {
            qtype: 1.into(),
            link_address: "0::0".parse().unwrap(),
            opts: LqQueryOptions::default(),
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = LqQuery::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = LqQuery::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
