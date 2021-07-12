use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    decoder::{Decodable, Decoder},
    error::DecodeResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOptions(HashMap<OptionCode, DhcpOption>);

impl<'r> Decodable<'r> for DhcpOptions {
    fn read(decoder: &'_ mut Decoder<'r>) -> DecodeResult<Self> {
        // represented as a vector in the actual message
        let mut opts = HashMap::new();
        // should we error the whole parser if we fail to parse an
        // option or just stop parsing options? -- here we will just stop
        while let Ok(opt) = DhcpOption::read(decoder) {
            match opt {
                DhcpOption::End => {
                    break;
                }
                _ => {
                    opts.insert(OptionCode::from(&opt), opt);
                }
            }
        }
        Ok(DhcpOptions(opts))
    }
}

#[derive(Debug, Copy, Hash, Clone, PartialEq, Eq)]
pub enum OptionCode {
    /// 0 Padding
    Pad,
    /// 1 Subnet Mask
    SubnetMask,
    /// 2 Time Offset
    TimeOffset,
    /// 3 Router
    Router,
    /// 4 Router
    TimeServer,
    /// 5 Name Server
    NameServer,
    /// 6 Name Server
    DomainNameServer,
    /// 7 Log Server
    LogServer,
    /// 8 Quote Server
    QuoteServer,
    /// 9 LPR Server
    LprServer,
    /// 10 Impress server
    ImpressServer,
    /// 11 Resource Location Server
    ResourceLocationServer,
    /// 12 Host name
    Hostname,
    /// 50 Requested IP Address
    RequestedIpAddress,
    /// 51 IP Address Lease Time
    AddressLeaseTime,
    /// 52 Option Overload
    OptionOverload,
    /// 53 Message Type
    MessageType,
    /// 54 Server Identifier
    ServerIdentifier,
    /// 55 Parameter Request List
    ParameterRequestList,
    /// 56 Message
    Message,
    /// 57 Maximum DHCP Message Size
    MaximumSize,
    /// 58 Renewal (T1) Time Value
    Renewal,
    /// 59 Rebinding (T2) Time Value
    Rebinding,
    /// 60 Class-identifier
    ClassIdentifier,
    /// 61 Client Identifier
    ClientIdentifier,
    /// Unknown option
    Unknown(u8),
    /// 255 End
    End,
}

impl From<u8> for OptionCode {
    fn from(n: u8) -> Self {
        use OptionCode::*;
        match n {
            0 => Pad,
            1 => SubnetMask,
            2 => TimeOffset,
            3 => Router,
            4 => TimeServer,
            5 => NameServer,
            6 => DomainNameServer,
            7 => LogServer,
            8 => QuoteServer,
            9 => LprServer,
            10 => ImpressServer,
            11 => ResourceLocationServer,
            12 => Hostname,
            50 => RequestedIpAddress,
            51 => AddressLeaseTime,
            52 => OptionOverload,
            53 => MessageType,
            54 => ServerIdentifier,
            55 => ParameterRequestList,
            56 => Message,
            57 => MaximumSize,
            58 => Renewal,
            59 => Rebinding,
            60 => ClassIdentifier,
            61 => ClientIdentifier,
            255 => End,
            // TODO: implement more
            n => Unknown(n),
        }
    }
}

impl From<OptionCode> for u8 {
    fn from(opt: OptionCode) -> Self {
        use OptionCode::*;
        match opt {
            Pad => 0,
            SubnetMask => 1,
            TimeOffset => 2,
            Router => 3,
            TimeServer => 4,
            NameServer => 5,
            DomainNameServer => 6,
            LogServer => 7,
            QuoteServer => 8,
            LprServer => 9,
            ImpressServer => 10,
            ResourceLocationServer => 11,
            Hostname => 12,
            RequestedIpAddress => 50,
            AddressLeaseTime => 51,
            OptionOverload => 52,
            MessageType => 53,
            ServerIdentifier => 54,
            ParameterRequestList => 55,
            Message => 56,
            MaximumSize => 57,
            Renewal => 58,
            Rebinding => 59,
            ClassIdentifier => 60,
            ClientIdentifier => 61,
            End => 255,
            // TODO: implement more
            Unknown(n) => n,
        }
    }
}

/// DHCP Options
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// 0 Padding
    Pad,
    /// 1 Subnet Mask
    SubnetMask(Ipv4Addr),
    /// 2 Time Offset
    TimeOffset(i32),
    /// 3 Router
    Router(Vec<Ipv4Addr>),
    /// 4 Router
    TimeServer(Vec<Ipv4Addr>),
    /// 5 Name Server
    NameServer(Vec<Ipv4Addr>),
    /// 6 Name Server
    DomainNameServer(Vec<Ipv4Addr>),
    /// 7 Log Server
    LogServer(Vec<Ipv4Addr>),
    /// 8 Quote Server
    QuoteServer(Vec<Ipv4Addr>),
    /// 9 LPR Server
    LprServer(Vec<Ipv4Addr>),
    /// 10 Impress server
    ImpressServer(Vec<Ipv4Addr>),
    /// 11 Resource Location Server
    ResourceLocationServer(Vec<Ipv4Addr>),
    /// 12 Host name
    Hostname(Vec<u8>),
    /// 50 Requested IP Address
    RequestedIpAddress(Ipv4Addr),
    /// 51 IP Address Lease Time
    AddressLeaseTime(u32),
    /// 52 Option Overload
    OptionOverload(u8),
    /// 53 Message Type
    MessageType(MessageType),
    /// 54 Server Identifier
    ServerIdentifier(Ipv4Addr),
    /// 55 Parameter Request List
    ParameterRequestList(Vec<u8>),
    /// 56 Message
    Message(Vec<u8>),
    /// 57 Maximum DHCP Message Size
    MaximumSize(u16),
    /// 58 Renewal (T1) Time Value
    Renewal(u32),
    /// 59 Rebinding (T2) Time Value
    Rebinding(u32),
    /// 60 Class-identifier
    ClassIdentifier(Vec<u8>),
    /// 61 Client Identifier
    ClientIdentifier(Vec<u8>),
    /// Unknown option
    Unknown(UnknownOption),
    /// 255 End
    End,
}

impl<'r> Decodable<'r> for DhcpOption {
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        use DhcpOption::*;
        // read the code first, determines the variant
        Ok(match decoder.read_u8()?.into() {
            OptionCode::Pad => Pad,
            OptionCode::SubnetMask => SubnetMask(read_ip(decoder)?),

            OptionCode::TimeOffset => {
                let _ = decoder.read_u8()?;
                TimeOffset(decoder.read_i32()?)
            }
            OptionCode::Router => Router(read_ips(decoder)?),
            OptionCode::TimeServer => TimeServer(read_ips(decoder)?),
            OptionCode::NameServer => NameServer(read_ips(decoder)?),
            OptionCode::DomainNameServer => DomainNameServer(read_ips(decoder)?),
            OptionCode::LogServer => LogServer(read_ips(decoder)?),
            OptionCode::QuoteServer => QuoteServer(read_ips(decoder)?),
            OptionCode::LprServer => LprServer(read_ips(decoder)?),
            OptionCode::ImpressServer => ImpressServer(read_ips(decoder)?),
            OptionCode::ResourceLocationServer => ResourceLocationServer(read_ips(decoder)?),
            OptionCode::Hostname => {
                let length = decoder.read_u8()?;
                Hostname(decoder.read_slice(length as usize)?.to_vec())
            }
            OptionCode::RequestedIpAddress => RequestedIpAddress(read_ip(decoder)?),
            OptionCode::AddressLeaseTime => {
                let _ = decoder.read_u8()?;
                AddressLeaseTime(decoder.read_u32()?)
            }
            OptionCode::OptionOverload => {
                let _ = decoder.read_u8()?;
                OptionOverload(decoder.read_u8()?)
            }
            OptionCode::MessageType => {
                let _ = decoder.read_u8()?;
                MessageType(decoder.read_u8()?.into())
            }
            OptionCode::ServerIdentifier => ServerIdentifier(read_ip(decoder)?),
            OptionCode::ParameterRequestList => {
                let length = decoder.read_u8()?;
                ParameterRequestList(decoder.read_slice(length as usize)?.to_vec())
            }
            OptionCode::Message => {
                let length = decoder.read_u8()?;
                Message(decoder.read_slice(length as usize)?.to_vec())
            }
            OptionCode::MaximumSize => {
                let _ = decoder.read_u8()?;
                MaximumSize(decoder.read_u16()?)
            }
            OptionCode::Renewal => {
                let _ = decoder.read_u8()?;
                Renewal(decoder.read_u32()?)
            }
            OptionCode::Rebinding => {
                let _ = decoder.read_u8()?;
                Rebinding(decoder.read_u32()?)
            }
            OptionCode::ClassIdentifier => {
                let length = decoder.read_u8()?;
                ClassIdentifier(decoder.read_slice(length as usize)?.to_vec())
            }
            OptionCode::ClientIdentifier => {
                let length = decoder.read_u8()?;
                ClientIdentifier(decoder.read_slice(length as usize)?.to_vec())
            }
            OptionCode::End => End,
            // not yet implemented
            OptionCode::Unknown(code) => {
                let length = decoder.read_u8()?;
                let bytes = decoder.read_slice(length as usize)?.to_vec();
                Unknown(UnknownOption {
                    code,
                    length,
                    bytes,
                })
            }
        })
    }
}

#[inline]
fn read_ip(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Ipv4Addr> {
    let length = decoder.read_u8()?;
    let bytes = decoder.read_slice(length as usize)?;
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]].into())
}

#[inline]
fn read_ips(decoder: &'_ mut Decoder<'_>) -> DecodeResult<Vec<Ipv4Addr>> {
    let length = decoder.read_u8()?;
    let ips = decoder.read_slice(length as usize)?;
    Ok(ips
        .chunks(4)
        .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]].into())
        .collect())
}

impl From<&DhcpOption> for OptionCode {
    fn from(opt: &DhcpOption) -> Self {
        use DhcpOption::*;
        match opt {
            Pad => OptionCode::Pad,
            SubnetMask(_) => OptionCode::SubnetMask,
            TimeOffset(_) => OptionCode::TimeOffset,
            Router(_) => OptionCode::Router,
            TimeServer(_) => OptionCode::TimeServer,
            NameServer(_) => OptionCode::NameServer,
            DomainNameServer(_) => OptionCode::DomainNameServer,
            LogServer(_) => OptionCode::LogServer,
            QuoteServer(_) => OptionCode::QuoteServer,
            LprServer(_) => OptionCode::LprServer,
            ImpressServer(_) => OptionCode::ImpressServer,
            ResourceLocationServer(_) => OptionCode::ResourceLocationServer,
            Hostname(_) => OptionCode::Hostname,
            RequestedIpAddress(_) => OptionCode::RequestedIpAddress,
            AddressLeaseTime(_) => OptionCode::AddressLeaseTime,
            OptionOverload(_) => OptionCode::OptionOverload,
            MessageType(_) => OptionCode::MessageType,
            ServerIdentifier(_) => OptionCode::ServerIdentifier,
            ParameterRequestList(_) => OptionCode::ParameterRequestList,
            Message(_) => OptionCode::Message,
            MaximumSize(_) => OptionCode::MaximumSize,
            Renewal(_) => OptionCode::Renewal,
            Rebinding(_) => OptionCode::Rebinding,
            ClassIdentifier(_) => OptionCode::ClassIdentifier,
            ClientIdentifier(_) => OptionCode::ClientIdentifier,
            End => OptionCode::End,
            // TODO: implement more
            Unknown(n) => OptionCode::Unknown(n.code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOption {
    code: u8,
    length: u8,
    bytes: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Pack,
    Nak,
    Release,
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(n: u8) -> Self {
        match n {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Pack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            n => MessageType::Unknown(n),
        }
    }
}
impl From<MessageType> for u8 {
    fn from(m: MessageType) -> Self {
        match m {
            MessageType::Discover => 1,
            MessageType::Offer => 2,
            MessageType::Request => 3,
            MessageType::Decline => 4,
            MessageType::Pack => 5,
            MessageType::Nak => 6,
            MessageType::Release => 7,
            MessageType::Unknown(n) => n,
        }
    }
}
