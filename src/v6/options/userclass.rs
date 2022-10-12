use super::{
    DecodeResult, EncodeResult, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserClass {
	pub data: Vec<UserClassData>,
}

impl Decodable for UserClass {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
		let len = decoder.read_u16()?;
		let mut data = vec![];
		let mut decoder = Decoder::new(decoder.read_slice(len as usize)?);
		let mut remaining_len = len;
		while remaining_len > 0{
			let len = decoder.peek_u16()?;
			data.push(UserClassData::decode(&mut decoder)?);
			remaining_len -= len+2;
		}
        Ok(UserClass {
			data
        })
    }
}

impl Encodable for UserClass {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::UserClass.into())?;
		let mut data = vec![];
		let mut dataenc = Encoder::new(&mut data);
		for ucd in self.data.iter(){
			ucd.encode(&mut dataenc)?;
		}
        e.write_u16(data.len() as u16)?;
		e.write_slice(&data)?;
        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserClassData{
	pub data: Vec<u8>,
}

impl Decodable for UserClassData {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
		let len = decoder.read_u16()?;
        Ok(UserClassData {
			data: decoder.read_slice(len.into())?.into(),
        })
    }
}

impl Encodable for UserClassData {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(self.data.len() as u16)?;
		e.write_slice(&self.data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_userclass_encode_decode() {
        let option = UserClass {
			data: vec![UserClassData{data:vec![1,2,3,4]},UserClassData{data:vec![1]},UserClassData{data:vec![1,2]}],
		};

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
		
        let decoded = UserClass::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = UserClass::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
