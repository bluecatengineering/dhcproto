//use std::net::Ipv4Addr;

use macaddr::*;
use std::convert::{TryFrom, TryInto};
use std::net::Ipv4Addr;

use crate::decoder::{Decodable, Decoder};
use crate::error::*;

/// [Dynamic Host Configuration Protocol](https://tools.ietf.org/html/rfc2131#section-2)
///
///```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
/// +---------------+---------------+---------------+---------------+
/// |                            xid (4)                            |
/// +-------------------------------+-------------------------------+
/// |           secs (2)            |           flags (2)           |
/// +-------------------------------+-------------------------------+
/// |                          ciaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          yiaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          siaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          giaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          chaddr  (16)                         |
/// +---------------------------------------------------------------+
/// |                          sname   (64)                         |
/// +---------------------------------------------------------------+
/// |                          file    (128)                        |
/// +---------------------------------------------------------------+
/// |                          options (variable)                   |
/// +---------------------------------------------------------------+
/// ```
#[derive(Debug)]
struct Message {
    /// op code / message type
    opcode: Opcode,
    /// Hardware address type: https://tools.ietf.org/html/rfc3232
    htype: u8,
    /// Hardware address length
    hlen: u8,
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    hops: u8,
    /// Transaction ID, a random number chosen by the client
    xid: u32,
    /// seconds elapsed since client began address acquisition or renewal process
    secs: u16,
    flags: u16, // todo: struct with a bool?
    /// Client IP address
    ciaddr: Ipv4Addr,
    /// Your IP Address,
    yiaddr: Ipv4Addr,
    /// Server IP Address   
    siaddr: Ipv4Addr,
    /// Gateway IP Address
    giaddr: Ipv4Addr,
    /// Client hardware addres
    chaddr: ChAddr,
    /// Server host name
    sname: Vec<u8>,
    /// Boot filename
    file: Vec<u8>,
    // TODO options
}

impl<'r> Decodable<'r> for Message {
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        let opcode = Opcode::read(decoder)?;
        let htype = decoder.read_u8()?;
        let hlen = decoder.read_u8()?;
        let hops = decoder.read_u8()?;
        let xid = decoder.read_u32()?;
        let secs = decoder.read_u16()?;
        let flags = decoder.read_u16()?;
        let ciaddr: Ipv4Addr = decoder.read_u32()?.into();
        let yiaddr: Ipv4Addr = decoder.read_u32()?.into();
        let siaddr: Ipv4Addr = decoder.read_u32()?.into();
        let giaddr: Ipv4Addr = decoder.read_u32()?.into();

        let mac = decoder.read_slice(hlen as usize)?;
        let chaddr: ChAddr = mac.try_into()?;

        let sname: Vec<u8> = decoder.read_slice(64)?.into();
        let file: Vec<u8> = decoder.read_slice(128)?.into();

        Ok(Message {
            opcode,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
        })
    }
}

#[derive(Debug)]
enum Opcode {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl<'r> Decodable<'r> for Opcode {
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(decoder.read_u8()?.into())
    }
}

impl From<u8> for Opcode {
    fn from(opcode: u8) -> Self {
        match opcode {
            1 => Opcode::BootRequest,
            2 => Opcode::BootReply,
            _ => Opcode::Unknown(opcode),
        }
    }
}

struct Flags {
    broadcast: bool,
    mbz: u16,
}

#[derive(Debug)]
enum ChAddr {
    Addr6(MacAddr6),
    Addr8(MacAddr8),
    Unknown(Vec<u8>),
}

impl TryFrom<&[u8]> for ChAddr {
    type Error = DecodeError;
    fn try_from(addr: &[u8]) -> DecodeResult<Self> {
        let mac = match addr.len() {
            6 => {
                let array = <[u8; 6]>::try_from(addr)?;
                ChAddr::Addr6(MacAddr6::from(array))
            }
            8 => {
                let array = <[u8; 8]>::try_from(addr)?;
                ChAddr::Addr8(MacAddr8::from(array))
            }
            _ => ChAddr::Unknown(addr.into()),
        };
        Ok(mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn decode_offer() -> Result<()> {
        let offer = dhcp_offer();
        let mut decoder = Decoder::new(offer.as_slice());
        let msg = Message::read(&mut decoder);
        dbg!(msg);
        Ok(())
    }

    fn dhcp_offer() -> Vec<u8> {
        vec![
            0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x15, 0x5c, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xc0, 0xa8, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xcc, 0x00, 0x0a, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0x33, 0x04, 0x00,
            0x00, 0x00, 0x3c, 0x3a, 0x04, 0x00, 0x00, 0x00, 0x1e, 0x3b, 0x04, 0x00, 0x00, 0x00,
            0x34, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0x06,
            0x08, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }
}
