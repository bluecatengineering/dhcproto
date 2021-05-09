use std::{convert::TryInto, net::Ipv4Addr};

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
    /// 50 Requested IP Address
    RequestedIpAddress(Ipv4Addr),
    /// 51 IP Address Lease Time
    AddressLeaseTime(u32),
    /// 52 Option Overload
    OptionOverload(u8),
    /// 53 Message Type
    MessageType(u8),
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
        let code = decoder.read_u8()?;
        Ok(match code {
            0 => Pad,
            1 => {
                let length = decoder.read_u8()?;
                let bytes = decoder.read_slice(length as usize)?.to_vec();
                let ip: Ipv4Addr = [bytes[0], bytes[1], bytes[2], bytes[3]].into();
                SubnetMask(ip)
            }
            2 => {
                let _ = decoder.read_u8()?;
                // length is always 4 here
                TimeOffset(decoder.read_i32()?)
            }
            50 => {
                let length = decoder.read_u8()?;
                let bytes = decoder.read_slice(length as usize)?.to_vec();
                let ip: Ipv4Addr = [bytes[0], bytes[1], bytes[2], bytes[3]].into();
                RequestedIpAddress(ip)
            }
            51 => {
                let _ = decoder.read_u8()?;
                // length is always 4 here
                AddressLeaseTime(decoder.read_u32()?)
            }
            52 => {
                let _ = decoder.read_u8()?;
                // length is always 1 here
                OptionOverload(decoder.read_u8()?)
            }
            54 => {
                let length = decoder.read_u8()?;
                let bytes = decoder.read_slice(length as usize)?.to_vec();
                let ip: Ipv4Addr = [bytes[0], bytes[1], bytes[2], bytes[3]].into();
                ServerIdentifier(ip)
            }
            255 => End,
            _ => {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOption {
    code: u8,
    length: u8,
    bytes: Vec<u8>,
}
