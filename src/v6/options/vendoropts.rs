use super::{
    DecodeResult,  EncodeResult,  OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Vendor defined options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOpts {
    pub enterprise_number: u32,
    pub opts: Vec<VendorOption>,
}

impl Decodable for VendorOpts {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
		let len = decoder.read_u16()?;
		let enterprise_number = decoder.read_u32()?;
		let mut opts = vec![];
		let mut used_len = 4;
		while used_len < len{
			let opt = VendorOption::decode(decoder)?;
			used_len += opt.len() + 4;
			opts.push(opt);
		}
        Ok(VendorOpts {
			enterprise_number,
			opts,
        })
    }
}

impl Encodable for VendorOpts {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
		let mut data = vec![];
		let mut enc = Encoder::new(&mut data);
		for opt in self.opts.iter(){
			opt.encode(&mut enc)?;
		}
        e.write_u16(OptionCode::VendorOpts.into())?;
		e.write_u16(data.len() as u16 + 4)?;
		e.write_u32(self.enterprise_number)?;
		e.write_slice(&data)?;
        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOption{
	pub code: u16,
	pub data: Vec<u8>,
}

impl VendorOption{
	fn len(&self) -> u16{
		self.data.len() as u16
	}
}

impl Decodable for VendorOption {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
		let code = decoder.read_u16()?;
		let len = decoder.read_u16()?;
        Ok(VendorOption {
			code,
			data: decoder.read_slice(len.into())?.into(),
        })
    }
}

impl Encodable for VendorOption {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
		e.write_u16(self.code)?;
        e.write_u16(self.data.len() as u16)?;
		e.write_slice(&self.data)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vendoropts_encode_decode() {
        let option = VendorOpts {
            enterprise_number: 0xABCD,
			opts: vec![VendorOption{code: 0xABCD, data: vec![1,2]},VendorOption{code: 0xACBD, data: vec![1,2,3]}],
        };

        let mut encoder = vec![];

        option.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = VendorOpts::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(option, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = VendorOpts::decode(&mut decoder).unwrap();
        assert_eq!(option, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
