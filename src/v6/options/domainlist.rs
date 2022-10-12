use trust_dns_proto::{
    rr::Name,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

use super::{DecodeResult, Domain, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainList {
    pub domains: Vec<Domain>,
}

impl Decodable for DomainList {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()?;
        let mut name_decoder = BinDecoder::new(decoder.read_slice(len as usize)?);
        let mut names = Vec::new();
        while let Ok(name) = Name::read(&mut name_decoder) {
            names.push(Domain(name));
        }

        Ok(DomainList { domains: names })
    }
}

impl Encodable for DomainList {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::DomainList.into())?;
        let mut buf = Vec::new();
        let mut name_encoder = BinEncoder::new(&mut buf);
        for name in self.domains.iter() {
            name.0.emit(&mut name_encoder)?;
        }
        e.write_u16(buf.len() as u16)?;
        e.write_slice(&buf)?;
        Ok(())
    }
}
