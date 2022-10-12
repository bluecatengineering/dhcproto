use std::net::Ipv6Addr;

use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSServers {
    pub servers: Vec<Ipv6Addr>,
}

impl Decodable for DNSServers {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
		let len = decoder.read_u16()?;
		let mut servers = vec![];
		for _ in 0..(len/16){
			servers.push(decoder.read::<16>()?.into());
		}
		
        Ok(DNSServers {
            servers,
        })
    }
}

impl Encodable for DNSServers {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::DNSServers.into())?;
        e.write_u16((self.servers.len()*16) as u16)?;
		for ip in self.servers.iter(){
			e.write_slice(&ip.octets())?;
		}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dns_servrs_encode_decode() {
        let option = DNSServers {
			servers: vec!["FE80:ABCD:EF12::1".parse::<Ipv6Addr>().unwrap()]
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
		println!("{:?}", encoder);
        let decoded = DNSServers::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = DNSServers::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
