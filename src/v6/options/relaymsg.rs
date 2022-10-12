use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMsg {
    pub msg: Vec<u8>,
}

impl Decodable for RelayMsg {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()? as usize;
        
        Ok(RelayMsg {
            msg: decoder.read_slice(len)?.into(),
        })
    }
}

impl Encodable for RelayMsg {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::RelayMsg.into())?;
        e.write_u16(self.msg.len() as u16)?;
        e.write_slice(&self.msg)?;
        Ok(())
    }
}

//impl From<RelayMsg> for Message?

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_server_id_encode_decode() {
        let option = RelayMsg {
            msg: vec![1,2,3],
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = RelayMsg::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = RelayMsg::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
