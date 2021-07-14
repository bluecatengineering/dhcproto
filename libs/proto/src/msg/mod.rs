use std::net::Ipv4Addr;

mod flags;
mod htype;
mod opcode;
mod options;

// re-export submodules from proto::msg
pub use self::{flags::*, htype::*, opcode::*, options::*};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::*,
};

const MAGIC: [u8; 4] = [99, 130, 83, 99];

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// op code / message type
    opcode: Opcode,
    /// Hardware address type: https://tools.ietf.org/html/rfc3232
    htype: HType,
    /// Hardware address length
    hlen: u8,
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    hops: u8,
    /// Transaction ID, a random number chosen by the client
    xid: u32,
    /// seconds elapsed since client began address acquisition or renewal process
    secs: u16,
    /// Flags
    flags: Flags,
    /// Client IP
    ciaddr: Ipv4Addr,
    /// Your IP
    yiaddr: Ipv4Addr,
    /// Server IP
    siaddr: Ipv4Addr,
    /// Gateway IP
    giaddr: Ipv4Addr,
    /// Client hardware address
    chaddr: [u8; 16],
    /// Server hostname
    sname: Option<String>,
    // File name
    file: Option<String>,
    magic: [u8; 4],
    options: DhcpOptions,
}

impl<'r> Decodable<'r> for Message {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(Message {
            opcode: Opcode::decode(decoder)?,
            htype: decoder.read_u8()?.into(),
            hlen: decoder.read_u8()?,
            hops: decoder.read_u8()?,
            xid: decoder.read_u32()?,
            secs: decoder.read_u16()?,
            flags: decoder.read_u16()?.into(),
            ciaddr: decoder.read_u32()?.into(),
            yiaddr: decoder.read_u32()?.into(),
            siaddr: decoder.read_u32()?.into(),
            giaddr: decoder.read_u32()?.into(),
            chaddr: decoder.read::<16>()?,
            sname: decoder.read_const_string::<64>()?,
            file: decoder.read_const_string::<128>()?,
            // TODO: check magic bytes against expected?
            magic: decoder.read::<4>()?,
            options: DhcpOptions::decode(decoder)?,
        })
    }
}

impl<'a> Encodable<'a> for Message {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<usize> {
        let mut len = 0;
        len += self.opcode.encode(e)?;
        len += self.htype.encode(e)?;
        len += e.write_u8(self.hlen)?;
        len += e.write_u8(self.hops)?;
        len += e.write_u32(self.xid)?;
        len += e.write_u16(self.secs)?;
        len += e.write_u16(self.flags.into())?;
        len += e.write_u32(self.ciaddr.into())?;
        len += e.write_u32(self.yiaddr.into())?;
        len += e.write_u32(self.siaddr.into())?;
        len += e.write_u32(self.giaddr.into())?;
        len += e.write_slice(&self.chaddr[..])?;
        len += e.write_fill_string(&self.sname, 64)?;
        len += e.write_fill_string(&self.file, 128)?;

        len += e.write(self.magic)?;
        self.options.encode(e)?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn decode_offer() -> Result<()> {
        // decode
        let offer = dhcp_offer();
        let msg = Message::decode(&mut Decoder::new(&offer))?;
        dbg!(&msg);
        dbg!(offer.len());
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        println!("{:?}", &buf);
        println!("{:?}", &dhcp_offer());
        // len will be different because input has arbitrary PAD bytes
        // assert_eq!(buf.len(), dhcp_offer().len());
        // decode again
        let res = Message::decode(&mut Decoder::new(&buf))?;
        // check Messages are equal after decoding/encoding
        assert_eq!(msg, res);
        Ok(())
    }

    #[test]
    fn decode_bootreq() -> Result<()> {
        println!("{:02x?}", &MAGIC[..]);
        let offer = dhcp_bootreq();
        let msg = Message::decode(&mut Decoder::new(&offer))?;
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        assert_eq!(buf, dhcp_bootreq());
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
    fn dhcp_bootreq() -> Vec<u8> {
        vec![
            1u8, // op
            2,   // htype
            3,   // hlen
            4,   // ops
            5, 6, 7, 8, // xid
            9, 10, // secs
            11, 12, // flags
            13, 14, 15, 16, // ciaddr
            17, 18, 19, 20, // yiaddr
            21, 22, 23, 24, // siaddr
            25, 26, 27, 28, // giaddr
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, // chaddr
            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
            67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
            89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            0, // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 0, 0, 0, 0, 0, 0, 0,
            0, // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",
            99, 130, 83, 99, // magic cookie
        ]
    }
}
