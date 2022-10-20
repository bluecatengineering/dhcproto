use super::{
    option_builder, ClientId, DecodeResult, DhcpOption, EncodeResult, IAAddr, IAPrefix, OptionCode,
};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Vendor defined options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientData {
    pub opts: ClientDataOptions,
}

impl Decodable for ClientData {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<2>()?;
        let len = decoder.read_u16()?;
        let mut decoder = Decoder::new(decoder.read_slice(len.into())?);

        Ok(ClientData {
            opts: ClientDataOptions::decode(&mut decoder)?,
        })
    }
}

impl Encodable for ClientData {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        let mut data = vec![];
        let mut enc = Encoder::new(&mut data);
        self.opts.encode(&mut enc)?;
        e.write_u16(OptionCode::ClientData.into())?;
        e.write_u16(data.len() as u16)?;
        e.write_slice(&data)?;
        Ok(())
    }
}

//TODO: add ORO reply options
option_builder!(
    ClientDataOption,
    ClientDataOptions,
    IsClientDataOption,
    DhcpOption,
    ClientId,
    IAAddr,
    IAPrefix,
    CltTime
);

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CltTime {
    ///seconds since server last communicated with the client (on that link)
    pub time: u32,
}

impl Decodable for CltTime {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        decoder.read::<4>()?;

        Ok(CltTime {
            time: decoder.read_u32()?,
        })
    }
}

impl Encodable for CltTime {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::CltTime.into())?;
        e.write_u16(4)?;
        e.write_u32(self.time)?;
        Ok(())
    }
}
