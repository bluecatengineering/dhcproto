use std::{collections::HashMap, net::Ipv6Addr};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::MessageType,
};

// TODO: read the RFC a few times and it's a little unclear to me
// if there if the definition of "singleton" refers to top-level
// or includes "encapsulated options". For instance, IANA has nested
// opts, if there's only one IANA allowed on each level then a map
// is okay. If we need to allow multiple IANA's per level, then
// we need a list.
// Also, implementations in the wild seem to use a hashmap for
// dhcpv6 opts. So?
// see: https://datatracker.ietf.org/doc/html/rfc8415#section-24

/// https://datatracker.ietf.org/doc/html/rfc8415#section-21
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOptions(Vec<DhcpOption>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    // 1 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.2
    ClientId(Vec<u8>), // should duid for this be bytes or string?
    // 2 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.3
    ServerId(Vec<u8>),
    // 3 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.4
    IANA(IANA),
    // 4 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.5
    IATA(IATA),
    // 5 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.6
    IAAddr(IAAddr),
    // 6 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.7
    ORO(ORO),
    // 7 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.8
    Preference(Preference),
    // 8 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.9
    ElapsedTime(ElapsedTime),
    // 9 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.10
    RelayMsg(RelayMsg),
    // 11 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.11
    Authentication(Authentication),
    // 12 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.12
    ServerUnicast(ServerUnicast),
    // 13 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.13
    StatusCode(StatusCode),
    // 14 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.14
    RapidCommit,
    // 15 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.15
    UserClass(UserClass),
    // 16 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.16
    VendorClass(VendorClass),
    // 17 -  https://datatracker.ietf.org/doc/html/rfc8415#section-21.17
    VendorOpts(VendorOpts),
    // 18 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.18
    InterfaceId(InterfaceId),
    // 19 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.19
    ReconfMsg(ReconfMsg),
    // 20 - https://datatracker.ietf.org/doc/html/rfc8415#section-21.20
    ReconfAccept,
    Unknown(UnknownOption),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceId {
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOpts {
    num: u32,
    // encapsulated options values
    opts: DhcpOptions,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ReconfMsg {
    msg_type: MessageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VendorClass {
    number: u32,
    data: Vec<String>,
    // each item in data is [len (2 bytes) | data]
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserClass {
    data: Vec<String>,
    // each item in data is [len (2 bytes) | data]
}

/// Server Unicast
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusCode {
    status: Status,
    // 2 + len
    msg: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
    Unknown(u8),
}

impl From<u8> for Status {
    fn from(n: u8) -> Self {
        use Status::*;
        match n {
            0 => Success,
            1 => UnspecFail,
            2 => NoAddrsAvail,
            3 => NoBinding,
            4 => NotOnLink,
            5 => UseMulticast,
            6 => NoPrefixAvail,
            _ => Unknown(n),
        }
    }
}
impl From<Status> for u8 {
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
            Unknown(n) => n,
        }
    }
}

/// Server Unicast
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ServerUnicast {
    addr: Ipv6Addr,
}

/// Authentication
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authentication {
    proto: u8,
    algo: u8,
    rdm: u8,
    replay_detection: u64,
    // 11 + len
    info: Vec<u8>,
}

/// Relay Msg
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

/// Elapsed Time
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ElapsedTime {
    elapsed: u16,
}

/// Preference
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Preference {
    pref: u8,
}

/// Option Request Option
/// https://datatracker.ietf.org/doc/html/rfc8415#section-21.7
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ORO {
    // 2 * num opts
    opts: Vec<OptionCode>,
}

/// Identity Association for Temporary Addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IATA {
    id: u32,
    // 4 + opts.len()
    // should this be Vec<DhcpOption> ?
    // the RFC suggests it 'encapsulates options'
    opts: DhcpOptions,
}

/// Identity Association for Non-Temporary Addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IANA {
    id: u32,
    t1: u32,
    t2: u32,
    // 12 + opts.len()
    opts: DhcpOptions,
}

/// Identity Association Address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAAddr {
    addr: Ipv6Addr,
    preferred_life: u32,
    valid_life: u32,
    // 24 + opts.len()
    // should this be DhcpOptions ?
    // the RFC suggests it 'encapsulates options'
    opts: DhcpOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption {
    code: u16,
    len: u16,
    bytes: Vec<u8>,
}

impl<'r> Decodable<'r> for DhcpOptions {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        let mut opts = Vec::new();
        while let Ok(opt) = DhcpOption::decode(decoder) {
            opts.push(opt);
        }
        Ok(DhcpOptions(opts))
    }
}

impl<'a> Encodable<'a> for DhcpOptions {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<()> {
        self.0.iter().map(|opt| opt.encode(e)).try_for_each(|n| n)
    }
}

impl<'r> Decodable<'r> for DhcpOption {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        let code = decoder.read_u16()?.into();
        let len = decoder.read_u16()? as usize;
        Ok(match code {
            OptionCode::ClientId => DhcpOption::ClientId(decoder.read_slice(len)?.to_vec()),
            OptionCode::ServerId => DhcpOption::ServerId(decoder.read_slice(len)?.to_vec()),
            OptionCode::IANA => {
                DhcpOption::IANA(IANA {
                    id: decoder.read_u32()?,
                    t1: decoder.read_u32()?,
                    t2: decoder.read_u32()?,
                    opts: {
                        // we need a new decoder but bounded to the len of where these
                        // encapsulated opts end
                        let mut opt_decoder = Decoder::new(decoder.read_slice(len - 12)?);
                        DhcpOptions::decode(&mut opt_decoder)?
                    },
                })
            }
            OptionCode::IATA => DhcpOption::IATA(IATA {
                id: decoder.read_u32()?,
                opts: {
                    let mut opt_decoder = Decoder::new(decoder.read_slice(len - 4)?);
                    DhcpOptions::decode(&mut opt_decoder)?
                },
            }),
            OptionCode::IAAddr => DhcpOption::IAAddr(IAAddr {
                addr: decoder.read::<16>()?.into(),
                preferred_life: decoder.read_u32()?,
                valid_life: decoder.read_u32()?,
                opts: {
                    let mut opt_decoder = Decoder::new(decoder.read_slice(len - 24)?);
                    DhcpOptions::decode(&mut opt_decoder)?
                },
            }),
            OptionCode::ORO => DhcpOption::ORO(ORO {
                opts: {
                    decoder
                        .read_slice(len)?
                        .chunks_exact(2)
                        // TODO: use .array_chunks::<2>() when stable
                        .map(|code| OptionCode::from(u16::from_be_bytes([code[0], code[1]])))
                        .collect()
                },
            }),
            OptionCode::Preference => DhcpOption::Preference(Preference {
                pref: decoder.read_u8()?,
            }),
            OptionCode::ElapsedTime => DhcpOption::ElapsedTime(ElapsedTime {
                elapsed: decoder.read_u16()?,
            }),
            OptionCode::RelayMsg => DhcpOption::RelayMsg(RelayMsg {
                msg: decoder.read_slice(len)?.to_vec(),
            }),
            OptionCode::Authentication => DhcpOption::Authentication(Authentication {
                proto: decoder.read_u8()?,
                algo: decoder.read_u8()?,
                rdm: decoder.read_u8()?,
                replay_detection: decoder.read_u64()?,
                info: decoder.read_slice(len - 11)?.to_vec(),
            }),
            OptionCode::ServerUnicast => DhcpOption::ServerUnicast(ServerUnicast {
                addr: decoder.read::<16>()?.into(),
            }),
            OptionCode::StatusCode => DhcpOption::StatusCode(StatusCode {
                status: decoder.read_u8()?.into(),
                msg: decoder.read_string(len)?,
            }),
            OptionCode::RapidCommit => DhcpOption::RapidCommit,
            OptionCode::UserClass => DhcpOption::UserClass(UserClass { data: todo!() }),
            OptionCode::VendorClass => DhcpOption::VendorClass(VendorClass {
                number: todo!(),
                data: todo!(),
            }),
            OptionCode::VendorOpts => DhcpOption::VendorOpts(VendorOpts {
                num: todo!(),
                opts: todo!(),
            }),
            OptionCode::InterfaceId => DhcpOption::InterfaceId(InterfaceId { id: todo!() }),
            OptionCode::ReconfMsg => DhcpOption::ReconfMsg(ReconfMsg { msg_type: todo!() }),
            OptionCode::ReconfAccept => DhcpOption::ReconfAccept,
            OptionCode::Unknown(code) => DhcpOption::Unknown(UnknownOption {
                code,
                len: len as u16,
                bytes: decoder.read_slice(len)?.to_vec(),
            }),
        })
    }
}
impl<'a> Encodable<'a> for DhcpOption {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<()> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCode {
    // 1
    ClientId, // should duid for this be bytes or string?
    // 2
    ServerId,
    // 3
    IANA,
    // 4
    IATA,
    // 5
    IAAddr,
    // 6
    ORO,
    // 7
    Preference,
    // 8
    ElapsedTime,
    // 9
    RelayMsg,
    // 11
    Authentication,
    // 12
    ServerUnicast,
    // 13
    StatusCode,
    // 14
    RapidCommit,
    // 15
    UserClass,
    // 16
    VendorClass,
    // 17
    VendorOpts,
    // 18
    InterfaceId,
    // 19
    ReconfMsg,
    // 20
    ReconfAccept,
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
            Unknown(UnknownOption { code, .. }) => OptionCode::Unknown(*code),
        }
    }
}
