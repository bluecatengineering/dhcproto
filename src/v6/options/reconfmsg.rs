use super::{
    DecodeResult, EncodeResult, OptionCode, MessageType,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconfMsg {
	msg_type: MessageType,
}

impl Decodable for ReconfMsg {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;
        Ok(ReconfMsg {
			msg_type: decoder.read_u8()?.into()
        })
    }
}

impl Encodable for ReconfMsg {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::ReconfMsg.into())?;
        e.write_u16(1)?;
		e.write_u8(self.msg_type.into())?;
        Ok(())
    }
}

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconfAccept {}

impl Decodable for ReconfAccept {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;
        Ok(ReconfAccept {
        })
    }
}

impl Encodable for ReconfAccept {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::ReconfAccept.into())?;
        e.write_u16(0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reconf_msg_encode_decode() {
        let option = ReconfMsg {
			msg_type: 1.into(),
		};

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = ReconfMsg::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = ReconfMsg::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
	#[test]
    fn test_reconf_accept_encode_decode() {
        let option = ReconfAccept {
		};

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = ReconfAccept::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = ReconfAccept::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
