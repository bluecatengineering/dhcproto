use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceId {
    pub id: Vec<u8>,
}

impl Decodable for InterfaceId {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        Ok(InterfaceId {
            id: decoder.read_slice(len)?.into(),
        })
    }
}

impl Encodable for InterfaceId {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::InterfaceId.into())?;
        e.write_u16(self.id.len() as u16)?;
        e.write_slice(&self.id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_interface_id_encode_decode() {
        let option = InterfaceId {
            id: vec![1,2,3,4],
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = InterfaceId::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = InterfaceId::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
