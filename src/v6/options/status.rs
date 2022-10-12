use crate::v6::{DecodeResult, EncodeResult, OptionCode};
use crate::{Decodable, Decoder, Encodable, Encoder};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusCode {
    pub status: Status,
    // 2 + len
    pub msg: String,
}

impl Decodable for StatusCode {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        let _code = decoder.read_u16()?;
        let len = decoder.read_u16()? as usize;
        Ok(StatusCode {
            status: decoder.read_u16()?.into(),
            msg: decoder.read_string(len - 2)?,
        })
    }
}

impl Encodable for StatusCode {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16(OptionCode::StatusCode.into())?;
        e.write_u16(2 + self.msg.len() as u16)?;
        e.write_u16(self.status.into())?;
        e.write_slice(self.msg.as_bytes())?;
        Ok(())
    }
}

/// Status code
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
    UnknownQueryType,
    MalformedQuery,
    NotConfigured,
    NotAllowed,
    QueryTerminated,
    DataMissing,
    CatchUpComplete,
    NotSupported,
    TLSConnectionRefused,
    AddressInUse,
    ConfigurationConflict,
    MissingBindingInformation,
    OutdatedBindingInformation,
    ServerShuttingDown,
    DNSUpdateNotSupported,
    ExcessiveTimeSkew,
    /// unknown/unimplemented message type
    Unknown(u16),
}

impl From<u16> for Status {
    fn from(n: u16) -> Self {
        use Status::*;
        match n {
            0 => Success,
            1 => UnspecFail,
            2 => NoAddrsAvail,
            3 => NoBinding,
            4 => NotOnLink,
            5 => UseMulticast,
            6 => NoPrefixAvail,
            7 => UnknownQueryType,
            8 => MalformedQuery,
            9 => NotConfigured,
            10 => NotAllowed,
            11 => QueryTerminated,
            12 => DataMissing,
            13 => CatchUpComplete,
            14 => NotSupported,
            15 => TLSConnectionRefused,
            16 => AddressInUse,
            17 => ConfigurationConflict,
            18 => MissingBindingInformation,
            19 => OutdatedBindingInformation,
            20 => ServerShuttingDown,
            21 => DNSUpdateNotSupported,
            22 => ExcessiveTimeSkew,
            _ => Unknown(n),
        }
    }
}
impl From<Status> for u16 {
    fn from(n: Status) -> Self {
        use Status::*;
        match n {
            Success => 0,
            UnspecFail => 1,
            NoAddrsAvail => 2,
            NoBinding => 3,
            NotOnLink => 4,
            UseMulticast => 5,
            NoPrefixAvail => 6,
            UnknownQueryType => 7,
            MalformedQuery => 8,
            NotConfigured => 9,
            NotAllowed => 10,
            QueryTerminated => 11,
            DataMissing => 12,
            CatchUpComplete => 13,
            NotSupported => 14,
            TLSConnectionRefused => 15,
            AddressInUse => 16,
            ConfigurationConflict => 17,
            MissingBindingInformation => 18,
            OutdatedBindingInformation => 19,
            ServerShuttingDown => 20,
            DNSUpdateNotSupported => 21,
            ExcessiveTimeSkew => 22,
            Unknown(n) => n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_status_code_encode_decode() {
        let sc = StatusCode {
            status: 0xABCDu16.into(),
            msg: "message".into(),
        };
        let mut encoder = vec![];

        sc.encode(&mut Encoder::new(&mut encoder)).unwrap();
        let decoded = StatusCode::decode(&mut Decoder::new(&encoder)).unwrap();
        assert_eq!(sc, decoded);

        encoder.push(50);
        let mut decoder = Decoder::new(&encoder);
        let decoded = StatusCode::decode(&mut decoder).unwrap();
        assert_eq!(sc, decoded);
        assert_eq!(50, decoder.read_u8().unwrap());
    }
}
