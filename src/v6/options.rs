#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::net::Ipv6Addr;

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::MessageType,
};

// server can send multiple IA_NA options to request multiple addresses
// this means we cannot represent is as a hashmap
// <https://datatracker.ietf.org/doc/html/rfc8415#section-6.6>

/// <https://datatracker.ietf.org/doc/html/rfc8415#section-21>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpOptions(Vec<DhcpOption>);

impl DhcpOptions {
    /// construct empty DhcpOptions
    pub fn new() -> Self {
        Self::default()
    }
    /// get the first element matching this option code
    pub fn get(&self, code: OptionCode) -> Option<&DhcpOption> {
        self.0
            .get(self.0.iter().position(|x| OptionCode::from(x) == code)?)
    }
    /// get the first element matching this option code
    pub fn get_mut(&mut self, code: OptionCode) -> Option<&mut DhcpOption> {
        let i = self.0.iter().position(|x| OptionCode::from(x) == code)?;
        self.0.get_mut(i)
    }
    /// remove the first element with a matching option code
    pub fn remove(&mut self, code: OptionCode) -> Option<DhcpOption> {
        Some(
            self.0
                .remove(self.0.iter().position(|x| OptionCode::from(x) == code)?),
        )
    }
    /// push a new option into the list of opts
    pub fn push(&mut self, opt: DhcpOption) {
        self.0.push(opt)
    }
    /// return a reference to an iterator
    pub fn iter(&self) -> impl Iterator<Item = &DhcpOption> {
        self.0.iter()
    }
    /// return a mutable ref to an iterator
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhcpOption> {
        self.0.iter_mut()
    }
}

/// DHCPv6 option types
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// 1 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.2>
    ClientId(Vec<u8>), // should duid for this be bytes or string?
    /// 2 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.3>
    ServerId(Vec<u8>),
    /// 3 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.4>
    IANA(IANA),
    /// 4 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.5>
    IATA(IATA),
    /// 5 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.6>
    IAAddr(IAAddr),
    /// 6 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.7>
    ORO(ORO),
    /// 7 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.8>
    Preference(u8),
    /// 8 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.9>
    /// Elapsed time in millis
    ElapsedTime(u16),
    /// 9 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.10>
    RelayMsg(RelayMsg),
    /// 11 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.11>
    Authentication(Authentication),
    /// 12 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.12>
    ServerUnicast(Ipv6Addr),
    /// 13 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.13>
    StatusCode(StatusCode),
    /// 14 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.14>
    RapidCommit,
    /// 15 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.15>
    UserClass(UserClass),
    /// 16 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.16>
    VendorClass(VendorClass),
    /// 17 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.17>
    VendorOpts(VendorOpts),
    /// 18 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.18>
    InterfaceId(Vec<u8>),
    /// 19 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.19>
    ReconfMsg(MessageType),
    /// 20 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.20>
    ReconfAccept,
    /// 23 - <https://datatracker.ietf.org/doc/html/rfc3646>
    DNSNameServer(Vec<Ipv6Addr>),
    /// 25 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.21>
    IAPD(IAPD),
    /// 26 - <https://datatracker.ietf.org/doc/html/rfc3633#section-10>
    IAPDPrefix(IAPDPrefix),
    /// An unknown or unimplemented option type
    Unknown(UnknownOption),
}

/// wrapper around interface id
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceId {
    pub id: String,
}

/// vendor options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOpts {
    pub num: u32,
    // encapsulated options values
    pub opts: DhcpOptions,
}

/// vendor class
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VendorClass {
    pub num: u32,
    pub data: Vec<Vec<u8>>,
    // each item in data is [len (2 bytes) | data]
}

/// user class
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserClass {
    pub data: Vec<Vec<u8>>,
    // each item in data is [len (2 bytes) | data]
}

#[inline]
fn decode_data(decoder: &'_ mut Decoder<'_>) -> Vec<Vec<u8>> {
    let mut data = Vec::new();
    while let Ok(len) = decoder.read_u16() {
        // if we can read the len and the string
        match decoder.read_slice(len as usize) {
            Ok(s) => data.push(s.to_vec()),
            // push, otherwise stop
            _ => break,
        }
    }
    data
}

/// Server Unicast
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusCode {
    pub status: Status,
    // 2 + len
    pub msg: String,
}

/// Status code for Server Unicast
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

/// Authentication
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authentication {
    pub proto: u8,
    pub algo: u8,
    pub rdm: u8,
    pub replay_detection: u64,
    // 11 + len
    pub info: Vec<u8>,
}

impl Decodable for Authentication {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        let len = decoder.buffer().len();
        Ok(Authentication {
            proto: decoder.read_u8()?,
            algo: decoder.read_u8()?,
            rdm: decoder.read_u8()?,
            replay_detection: decoder.read_u64()?,
            info: decoder.read_slice(len - 11)?.to_vec(),
        })
    }
}

/// Relay Msg
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayMsg {
    /// DHCP-relay-message In a Relay-forward message, the received
    ///                message, relayed verbatim to the next relay agent
    ///                or server; in a Relay-reply message, the message to
    ///                be copied and relayed to the relay agent or client
    ///                whose address is in the peer-address field of the
    ///                Relay-reply message
    // TODO: should we decode this into a `Message`?
    msg: Vec<u8>,
}

impl RelayMsg {
    /// Create a new `RelayMsg`
    pub fn new(msg: Vec<u8>) -> Self {
        Self { msg }
    }
    /// return the contents of the `RelayMsg`
    pub fn data(&self) -> &[u8] {
        &self.msg
    }
}

/// Option Request Option
/// <https://datatracker.ietf.org/doc/html/rfc8415#section-21.7>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ORO {
    // 2 * num opts
    pub opts: Vec<OptionCode>,
}

impl Decodable for ORO {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        let len = decoder.buffer().len();
        Ok(ORO {
            opts: {
                decoder
                    .read_slice(len)?
                    .chunks_exact(2)
                    // TODO: use .array_chunks::<2>() when stable
                    .map(|code| OptionCode::from(u16::from_be_bytes([code[0], code[1]])))
                    .collect()
            },
        })
    }
}

/// Identity Association for Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IATA {
    pub id: u32,
    // 4 + opts.len()
    // should this be Vec<DhcpOption> ?
    // the RFC suggests it 'encapsulates options'
    pub opts: DhcpOptions,
}

impl Decodable for IATA {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(IATA {
            id: decoder.read_u32()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

/// Identity Association for Non-Temporary Addresses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IANA {
    pub id: u32,
    pub t1: u32,
    pub t2: u32,
    // 12 + opts.len()
    pub opts: DhcpOptions,
}

impl Decodable for IANA {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(IANA {
            id: decoder.read_u32()?,
            t1: decoder.read_u32()?,
            t2: decoder.read_u32()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

/// Identity Association Prefix Delegation
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAPD {
    pub id: u32,
    pub t1: u32,
    pub t2: u32,
    // 12 + opts.len()
    pub opts: DhcpOptions,
}

impl Decodable for IAPD {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(IAPD {
            id: decoder.read_u32()?,
            t1: decoder.read_u32()?,
            t2: decoder.read_u32()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

/// Identity Association Prefix Delegation Prefix Option
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAPDPrefix {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub prefix_ip: Ipv6Addr,
    // 25 + opts.len()
    pub opts: DhcpOptions,
}

impl Decodable for IAPDPrefix {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(IAPDPrefix {
            preferred_lifetime: decoder.read_u32()?,
            valid_lifetime: decoder.read_u32()?,
            prefix_len: decoder.read_u8()?,
            prefix_ip: decoder.read::<16>()?.into(),
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

/// Identity Association Address
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAAddr {
    pub addr: Ipv6Addr,
    pub preferred_life: u32,
    pub valid_life: u32,
    // 24 + opts.len()
    // should this be DhcpOptions ?
    // the RFC suggests it 'encapsulates options'
    pub opts: DhcpOptions,
}

impl Decodable for IAAddr {
    fn decode(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(IAAddr {
            addr: decoder.read::<16>()?.into(),
            preferred_life: decoder.read_u32()?,
            valid_life: decoder.read_u32()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

/// fallback for options not yet implemented
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption {
    code: u16,
    data: Vec<u8>,
}

impl UnknownOption {
    pub fn new(code: OptionCode, data: Vec<u8>) -> Self {
        Self {
            code: code.into(),
            data,
        }
    }
    /// return the option code
    pub fn code(&self) -> OptionCode {
        self.code.into()
    }
    /// return the data for this option
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// consume option into its components
    pub fn into_parts(self) -> (OptionCode, Vec<u8>) {
        (self.code.into(), self.data)
    }
}

impl Decodable for DhcpOptions {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let mut opts = Vec::new();
        while let Ok(opt) = DhcpOption::decode(decoder) {
            opts.push(opt);
        }
        Ok(DhcpOptions(opts))
    }
}

impl Encodable for DhcpOptions {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        self.0.iter().try_for_each(|opt| opt.encode(e))
    }
}

impl Decodable for DhcpOption {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let code = decoder.read_u16()?.into();
        let len = decoder.read_u16()? as usize;
        Ok(match code {
            OptionCode::ClientId => DhcpOption::ClientId(decoder.read_slice(len)?.to_vec()),
            OptionCode::ServerId => DhcpOption::ServerId(decoder.read_slice(len)?.to_vec()),
            OptionCode::IANA => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::IANA(IANA::decode(&mut dec)?)
            }
            OptionCode::IATA => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::IATA(IATA::decode(&mut dec)?)
            }
            OptionCode::IAAddr => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::IAAddr(IAAddr::decode(&mut dec)?)
            }
            OptionCode::ORO => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::ORO(ORO::decode(&mut dec)?)
            }
            OptionCode::Preference => DhcpOption::Preference(decoder.read_u8()?),
            OptionCode::ElapsedTime => DhcpOption::ElapsedTime(decoder.read_u16()?),
            OptionCode::RelayMsg => DhcpOption::RelayMsg(RelayMsg {
                msg: decoder.read_slice(len)?.to_vec(),
            }),
            OptionCode::Authentication => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::Authentication(Authentication::decode(&mut dec)?)
            }
            OptionCode::ServerUnicast => DhcpOption::ServerUnicast(decoder.read::<16>()?.into()),
            OptionCode::StatusCode => DhcpOption::StatusCode(StatusCode {
                status: decoder.read_u16()?.into(),
                msg: decoder.read_string(len - 1)?,
            }),
            OptionCode::RapidCommit => DhcpOption::RapidCommit,
            OptionCode::UserClass => {
                let buf = decoder.read_slice(len)?;
                DhcpOption::UserClass(UserClass {
                    data: decode_data(&mut Decoder::new(buf)),
                })
            }
            OptionCode::VendorClass => {
                let num = decoder.read_u32()?;
                let buf = decoder.read_slice(len - 4)?;
                DhcpOption::VendorClass(VendorClass {
                    num,
                    data: decode_data(&mut Decoder::new(buf)),
                })
            }
            OptionCode::VendorOpts => DhcpOption::VendorOpts(VendorOpts {
                num: decoder.read_u32()?,
                opts: {
                    let mut opt_decoder = Decoder::new(decoder.read_slice(len - 4)?);
                    DhcpOptions::decode(&mut opt_decoder)?
                },
            }),
            OptionCode::InterfaceId => DhcpOption::InterfaceId(decoder.read_slice(len)?.to_vec()),
            OptionCode::ReconfMsg => DhcpOption::ReconfMsg(decoder.read_u8()?.into()),
            OptionCode::ReconfAccept => DhcpOption::ReconfAccept,
            OptionCode::DNSNameServer => DhcpOption::DNSNameServer(decoder.read_ipv6s(len)?),
            OptionCode::IAPD => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::IAPD(IAPD::decode(&mut dec)?)
            }
            OptionCode::IAPDPrefix => {
                let mut dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::IAPDPrefix(IAPDPrefix::decode(&mut dec)?)
            }
            // not yet implemented
            OptionCode::DomainSearchList => DhcpOption::Unknown(UnknownOption {
                code: code.into(),
                data: decoder.read_slice(len)?.to_vec(),
            }),
            OptionCode::Unknown(code) => DhcpOption::Unknown(UnknownOption {
                code,
                data: decoder.read_slice(len)?.to_vec(),
            }),
        })
    }
}
impl Encodable for DhcpOption {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        let code: OptionCode = self.into();
        e.write_u16(code.into())?;
        match self {
            DhcpOption::ClientId(duid) | DhcpOption::ServerId(duid) => {
                e.write_u16(duid.len() as u16)?;
                e.write_slice(duid)?;
            }
            DhcpOption::IANA(IANA { id, t1, t2, opts })
            | DhcpOption::IAPD(IAPD { id, t1, t2, opts }) => {
                // write len
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(12 + buf.len() as u16)?;
                // write data
                e.write_u32(*id)?;
                e.write_u32(*t1)?;
                e.write_u32(*t2)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::IATA(IATA { id, opts }) => {
                // write len
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(4 + buf.len() as u16)?;
                // data
                e.write_u32(*id)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::IAAddr(IAAddr {
                addr,
                preferred_life,
                valid_life,
                opts,
            }) => {
                // write len
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(24 + buf.len() as u16)?;
                // data
                e.write_u128((*addr).into())?;
                e.write_u32(*preferred_life)?;
                e.write_u32(*valid_life)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::ORO(ORO { opts }) => {
                // write len
                e.write_u16(2 * opts.len() as u16)?;
                // data
                for code in opts {
                    e.write_u16(u16::from(*code))?;
                }
            }
            DhcpOption::Preference(pref) => {
                e.write_u16(1)?;
                e.write_u8(*pref)?;
            }
            DhcpOption::ElapsedTime(elapsed) => {
                e.write_u16(2)?;
                e.write_u16(*elapsed)?;
            }
            DhcpOption::RelayMsg(RelayMsg { msg }) => {
                e.write_u16(msg.len() as u16)?;
                e.write_slice(msg)?;
            }
            DhcpOption::Authentication(Authentication {
                proto,
                algo,
                rdm,
                replay_detection,
                info,
            }) => {
                e.write_u16(11 + info.len() as u16)?;
                e.write_u8(*proto)?;
                e.write_u8(*algo)?;
                e.write_u8(*rdm)?;
                e.write_u64(*replay_detection)?;
                e.write_slice(info)?;
            }
            DhcpOption::ServerUnicast(addr) => {
                e.write_u16(16)?;
                e.write_u128((*addr).into())?;
            }
            DhcpOption::StatusCode(StatusCode { status, msg }) => {
                e.write_u16(2 + msg.len() as u16)?;
                e.write_u16((*status).into())?;
                e.write_slice(msg.as_bytes())?;
            }
            DhcpOption::RapidCommit => {
                e.write_u16(0)?;
            }
            DhcpOption::UserClass(UserClass { data }) => {
                e.write_u16(data.len() as u16)?;
                for s in data {
                    e.write_u16(s.len() as u16)?;
                    e.write_slice(s)?;
                }
            }
            DhcpOption::VendorClass(VendorClass { num, data }) => {
                e.write_u16(4 + data.len() as u16)?;
                e.write_u32(*num)?;
                for s in data {
                    e.write_u16(s.len() as u16)?;
                    e.write_slice(s)?;
                }
            }
            DhcpOption::VendorOpts(VendorOpts { num, opts }) => {
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(4 + buf.len() as u16)?;
                e.write_u32(*num)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::InterfaceId(id) => {
                e.write_u16(id.len() as u16)?;
                e.write_slice(id)?;
            }
            DhcpOption::ReconfMsg(msg_type) => {
                e.write_u16(1)?;
                e.write_u8((*msg_type).into())?;
            }
            DhcpOption::ReconfAccept => {
                e.write_u16(0)?;
            }
            DhcpOption::DNSNameServer(addrs) => {
                e.write_u16(addrs.len() as u16 * 16)?;
                for addr in addrs {
                    e.write_u128((*addr).into())?;
                }
            }
            DhcpOption::IAPDPrefix(IAPDPrefix {
                preferred_lifetime,
                valid_lifetime,
                prefix_len,
                prefix_ip,
                opts,
            }) => {
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(25 + buf.len() as u16)?;
                // write data
                e.write_u32(*preferred_lifetime)?;
                e.write_u32(*valid_lifetime)?;
                e.write_u8(*prefix_len)?;
                e.write_u128((*prefix_ip).into())?;
                e.write_slice(&buf)?;
            }
            DhcpOption::Unknown(UnknownOption { data, .. }) => {
                e.write_u16(data.len() as u16)?;
                e.write_slice(data)?;
            }
        };
        Ok(())
    }
}

/// option code type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCode {
    /// 1
    ClientId, // should duid for this be bytes or string?
    /// 2
    ServerId,
    /// 3
    IANA,
    /// 4
    IATA,
    /// 5
    IAAddr,
    /// 6
    ORO,
    /// 7
    Preference,
    /// 8
    ElapsedTime,
    /// 9
    RelayMsg,
    /// 11
    Authentication,
    /// 12
    ServerUnicast,
    /// 13
    StatusCode,
    /// 14
    RapidCommit,
    /// 15
    UserClass,
    /// 16
    VendorClass,
    /// 17
    VendorOpts,
    /// 18
    InterfaceId,
    /// 19
    ReconfMsg,
    /// 20
    ReconfAccept,
    /// 23
    DNSNameServer,
    /// 24
    DomainSearchList,
    /// 25
    IAPD,
    /// 26
    IAPDPrefix,
    /// an unknown or unimplemented option type
    Unknown(u16),
}

impl From<OptionCode> for u16 {
    fn from(opt: OptionCode) -> Self {
        use OptionCode::*;
        match opt {
            ClientId => 1,
            ServerId => 2,
            IANA => 3,
            IATA => 4,
            IAAddr => 5,
            ORO => 6,
            Preference => 7,
            ElapsedTime => 8,
            RelayMsg => 9,
            Authentication => 11,
            ServerUnicast => 12,
            StatusCode => 13,
            RapidCommit => 14,
            UserClass => 15,
            VendorClass => 16,
            VendorOpts => 17,
            InterfaceId => 18,
            ReconfMsg => 19,
            ReconfAccept => 20,
            DNSNameServer => 23,
            DomainSearchList => 24,
            IAPD => 25,
            IAPDPrefix => 26,
            Unknown(n) => n,
        }
    }
}

impl From<u16> for OptionCode {
    fn from(n: u16) -> Self {
        use OptionCode::*;
        match n {
            1 => ClientId,
            2 => ServerId,
            3 => IANA,
            4 => IATA,
            5 => IAAddr,
            6 => ORO,
            7 => Preference,
            8 => ElapsedTime,
            9 => RelayMsg,
            11 => Authentication,
            12 => ServerUnicast,
            13 => StatusCode,
            14 => RapidCommit,
            15 => UserClass,
            16 => VendorClass,
            17 => VendorOpts,
            18 => InterfaceId,
            19 => ReconfMsg,
            20 => ReconfAccept,
            23 => DNSNameServer,
            24 => DomainSearchList,
            25 => IAPD,
            26 => IAPDPrefix,
            _ => Unknown(n),
        }
    }
}

impl From<&DhcpOption> for OptionCode {
    fn from(opt: &DhcpOption) -> Self {
        use DhcpOption::*;
        match opt {
            ClientId(_) => OptionCode::ClientId,
            ServerId(_) => OptionCode::ServerId,
            IANA(_) => OptionCode::IANA,
            IATA(_) => OptionCode::IATA,
            IAAddr(_) => OptionCode::IAAddr,
            ORO(_) => OptionCode::ORO,
            Preference(_) => OptionCode::Preference,
            ElapsedTime(_) => OptionCode::ElapsedTime,
            RelayMsg(_) => OptionCode::RelayMsg,
            Authentication(_) => OptionCode::Authentication,
            ServerUnicast(_) => OptionCode::ServerUnicast,
            StatusCode(_) => OptionCode::StatusCode,
            RapidCommit => OptionCode::RapidCommit,
            UserClass(_) => OptionCode::UserClass,
            VendorClass(_) => OptionCode::VendorClass,
            VendorOpts(_) => OptionCode::VendorOpts,
            InterfaceId(_) => OptionCode::InterfaceId,
            ReconfMsg(_) => OptionCode::ReconfMsg,
            ReconfAccept => OptionCode::ReconfAccept,
            DNSNameServer(_) => OptionCode::DNSNameServer,
            IAPD(_) => OptionCode::IAPD,
            IAPDPrefix(_) => OptionCode::IAPDPrefix,
            Unknown(UnknownOption { code, .. }) => OptionCode::Unknown(*code),
        }
    }
}
