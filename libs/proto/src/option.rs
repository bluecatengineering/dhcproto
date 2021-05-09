use std::net::Ipv4Addr;

use crate::{
    decoder::{Decodable, Decoder},
    error::DecodeResult,
};

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
        Ok(match decoder.read_u8()? {
            0 => Pad,
            1 => SubnetMask(read_ip(decoder)?),
            2 => {
                let _ = decoder.read_u8()?;
                TimeOffset(decoder.read_i32()?)
            }
            3 => Router(read_ips(decoder)?),
            4 => TimeServer(read_ips(decoder)?),
            5 => NameServer(read_ips(decoder)?),
            6 => DomainNameServer(read_ips(decoder)?),
            7 => LogServer(read_ips(decoder)?),
            8 => QuoteServer(read_ips(decoder)?),
            9 => LprServer(read_ips(decoder)?),
            10 => ImpressServer(read_ips(decoder)?),
            11 => ResourceLocationServer(read_ips(decoder)?),
            12 => {
                let length = decoder.read_u8()?;
                Hostname(decoder.read_slice(length as usize)?.to_vec())
            }
            50 => RequestedIpAddress(read_ip(decoder)?),
            51 => {
                let _ = decoder.read_u8()?;
                AddressLeaseTime(decoder.read_u32()?)
            }
            52 => {
                let _ = decoder.read_u8()?;
                OptionOverload(decoder.read_u8()?)
            }
            53 => {
                let _ = decoder.read_u8()?;
                MessageType(decoder.read_u8()?.into())
            }
            54 => ServerIdentifier(read_ip(decoder)?),
            55 => {
                let length = decoder.read_u8()?;
                ParameterRequestList(decoder.read_slice(length as usize)?.to_vec())
            }
            56 => {
                let length = decoder.read_u8()?;
                Message(decoder.read_slice(length as usize)?.to_vec())
            }
            57 => {
                let _ = decoder.read_u8()?;
                MaximumSize(decoder.read_u16()?)
            }
            58 => {
                let _ = decoder.read_u8()?;
                Renewal(decoder.read_u32()?)
            }
            59 => {
                let _ = decoder.read_u8()?;
                Rebinding(decoder.read_u32()?)
            }
            60 => {
                let length = decoder.read_u8()?;
                ClassIdentifier(decoder.read_slice(length as usize)?.to_vec())
            }
            61 => {
                let length = decoder.read_u8()?;
                ClientIdentifier(decoder.read_slice(length as usize)?.to_vec())
            }
            255 => End,
            // not yet implemented
            code => {
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
    Pnak,
    Prelease,
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
            6 => MessageType::Pnak,
            7 => MessageType::Prelease,
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
            MessageType::Pnak => 6,
            MessageType::Prelease => 7,
            MessageType::Unknown(n) => n,
        }
    }
}
