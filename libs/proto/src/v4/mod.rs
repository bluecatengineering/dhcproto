//! DHCPv4 Message type
use std::{convert::TryInto, net::Ipv4Addr};

mod flags;
mod htype;
mod opcode;
mod options;

// re-export submodules from proto::msg
pub use self::{flags::*, htype::*, opcode::*, options::*};
pub use crate::{
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
    opts: DhcpOptions,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            opcode: Opcode::BootRequest,
            htype: HType::Eth,
            hlen: 0,
            hops: 0,
            xid: rand::random(),
            secs: 0,
            flags: Flags::default(),
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: None,
            file: None,
            magic: MAGIC,
            opts: DhcpOptions::default(),
        }
    }
}

impl Message {
    /// returns a new Message with OpCode set to BootRequest and a new random id
    /// # Panic
    ///   panics if chaddr is greater len than 16
    pub fn new(
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        chaddr: &[u8],
    ) -> Self {
        Self::new_with_id(rand::random(), ciaddr, yiaddr, siaddr, giaddr, chaddr)
    }

    /// returns a new Message with OpCode set to BootRequest
    /// # Panic
    ///   panics if chaddr is greater len than 16
    pub fn new_with_id(
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        chaddr: &[u8],
    ) -> Self {
        assert!(chaddr.len() <= 16);

        // copy our chaddr into static array
        let mut new_chaddr = [0; 16];
        let len = chaddr.len();
        new_chaddr[..len].copy_from_slice(chaddr);

        Self {
            hlen: chaddr.len() as u8,
            xid,
            flags: Flags::default().set_broadcast(),
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr: new_chaddr,
            ..Self::default()
        }
    }

    /// Get the message's opcode.
    /// op code / message type
    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// Set the message's opcode.
    /// op code / message type
    pub fn set_opcode(&mut self, opcode: Opcode) -> &mut Self {
        self.opcode = opcode;
        self
    }

    /// Get the message's hardware type.
    pub fn htype(&mut self) -> &HType {
        &self.htype
    }

    /// Set the message's hardware type.
    pub fn set_htype(&mut self, htype: HType) -> &mut Self {
        self.htype = htype;
        self
    }

    /// Get the message's hardware len (len of chaddr).
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Get the message's hops.
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// Set the message's hops.
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    pub fn set_hops(&mut self, hops: u8) -> &mut Self {
        self.hops = hops;
        self
    }

    /// Get the message's chaddr.
    pub fn chaddr(&self) -> &[u8] {
        &self.chaddr[..(self.hlen as usize)]
    }

    /// Set the message's hops.
    pub fn set_chaddr(&mut self, chaddr: &[u8]) -> &mut Self {
        let mut new_chaddr = [0; 16];
        new_chaddr.copy_from_slice(chaddr);
        self.hlen = chaddr.len() as u8;
        self.chaddr = new_chaddr;
        self
    }

    /// Get the message's giaddr.
    /// Gateway IP
    pub fn giaddr(&self) -> Ipv4Addr {
        self.giaddr
    }
    /// Set the message's giaddr.
    /// Gateway IP
    pub fn set_giaddr<I: Into<Ipv4Addr>>(&mut self, giaddr: I) -> &mut Self {
        self.giaddr = giaddr.into();
        self
    }

    /// Get the message's siaddr.
    /// Server IP
    pub fn siaddr(&self) -> Ipv4Addr {
        self.siaddr
    }
    /// Set the message's siaddr.
    /// Server IP
    pub fn set_siaddr<I: Into<Ipv4Addr>>(&mut self, siaddr: I) -> &mut Self {
        self.siaddr = siaddr.into();
        self
    }

    /// Get the message's yiaddr.
    /// Your IP
    /// In an OFFER this is the ip the server is offering
    pub fn yiaddr(&self) -> Ipv4Addr {
        self.yiaddr
    }

    /// Set the message's siaddr.
    /// Your IP
    pub fn set_yiaddr<I: Into<Ipv4Addr>>(&mut self, yiaddr: I) -> &mut Self {
        self.yiaddr = yiaddr.into();
        self
    }

    /// Get the message's ciaddr.
    /// Client IP
    pub fn ciaddr(&self) -> Ipv4Addr {
        self.ciaddr
    }

    /// Set the message's siaddr.
    /// Client IP
    pub fn set_ciaddr<I: Into<Ipv4Addr>>(&mut self, ciaddr: I) -> &mut Self {
        self.ciaddr = ciaddr.into();
        self
    }

    /// Get the message's flags.
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Set the message's flags.
    pub fn set_flags(&mut self, flags: Flags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Get the message's secs.
    pub fn secs(&self) -> u16 {
        self.secs
    }
    /// Set the message's secs.
    pub fn set_secs(&mut self, secs: u16) -> &mut Self {
        self.secs = secs;
        self
    }
    /// Get the message's xid.
    /// Transaction ID, a random number chosen by the client
    pub fn xid(&self) -> u32 {
        self.xid
    }
    /// Set the message's xid.
    /// Transaction ID, a random number chosen by the client
    pub fn set_xid(&mut self, xid: u32) -> &mut Self {
        self.xid = xid;
        self
    }
    /// Get a reference to the message's file.
    pub fn file(&self) -> Option<&String> {
        self.file.as_ref()
    }
    /// Set the message's file.
    /// # Panic
    ///     will panic if file is greater than 128 bytes long
    pub fn set_file<S: Into<String>>(&mut self, file: S) -> &mut Self {
        let file = file.into();
        assert!(file.len() <= 128);
        self.file = Some(file);
        self
    }
    /// Get a reference to the message's sname.
    pub fn sname(&self) -> Option<&String> {
        self.sname.as_ref()
    }
    /// Set the message's sname.
    /// # Panic
    ///     will panic if sname is greater than 64 bytes long
    pub fn set_sname<S: Into<String>>(&mut self, sname: S) -> &mut Self {
        let sname = sname.into();
        assert!(sname.len() <= 64);
        self.sname = Some(sname);
        self
    }
    /// Get a reference to the message's opts.
    pub fn opts(&self) -> &DhcpOptions {
        &self.opts
    }

    /// Set the DHCP options
    pub fn set_opts(&mut self, opts: DhcpOptions) -> &mut Self {
        self.opts = opts;
        self
    }

    /// Get a mutable reference to the message's options.
    pub fn opts_mut(&mut self) -> &mut DhcpOptions {
        &mut self.opts
    }
}

impl Decodable for Message {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
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
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

impl Encodable for Message {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        self.opcode.encode(e)?;
        self.htype.encode(e)?;
        e.write_u8(self.hlen)?;
        e.write_u8(self.hops)?;
        e.write_u32(self.xid)?;
        e.write_u16(self.secs)?;
        e.write_u16(self.flags.into())?;
        e.write_u32(self.ciaddr.into())?;
        e.write_u32(self.yiaddr.into())?;
        e.write_u32(self.siaddr.into())?;
        e.write_u32(self.giaddr.into())?;
        e.write_slice(&self.chaddr[..])?;
        e.write_fill_string(&self.sname, 64)?;
        e.write_fill_string(&self.file, 128)?;

        e.write(self.magic)?;
        self.opts.encode(e)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn decode_ipv4(input: Vec<u8>, expected: MessageType) -> Result<()> {
        // decode
        let msg = Message::decode(&mut Decoder::new(&input))?;
        dbg!(&msg);
        assert_eq!(msg.opts().msg_type().unwrap(), expected);
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        println!("{:?}", buf);
        println!("{:?}", input);
        // decode again
        let res = Message::decode(&mut Decoder::new(&buf))?;
        // check Messages are equal after decoding/encoding
        assert_eq!(msg, res);
        Ok(())
    }
    #[test]
    fn decode_offer() -> Result<()> {
        decode_ipv4(offer(), MessageType::Offer)?;
        Ok(())
    }

    #[test]
    fn decode_discover() -> Result<()> {
        decode_ipv4(discover(), MessageType::Discover)?;
        Ok(())
    }

    #[test]
    fn decode_offer_two() -> Result<()> {
        decode_ipv4(other_offer(), MessageType::Offer)?;
        Ok(())
    }

    #[test]
    fn decode_bootreq() -> Result<()> {
        let offer = bootreq();
        let msg = Message::decode(&mut Decoder::new(&offer))?;
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        assert_eq!(buf, bootreq());
        Ok(())
    }

    fn offer() -> Vec<u8> {
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
    fn bootreq() -> Vec<u8> {
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
    fn discover() -> Vec<u8> {
        vec![
            0x01, 0x01, 0x06, 0x00, 0xa6, 0x80, 0x56, 0x74, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xc0, 0xde, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
            0x53, 0x63, 0x35, 0x01, 0x01, 0x37, 0x40, 0xfc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
            0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x43,
            0x42, 0x33, 0x04, 0x00, 0x00, 0x00, 0x01, 0xff,
        ]
    }
    fn other_offer() -> Vec<u8> {
        vec![
            0x02, 0x01, 0x06, 0x00, 0xa6, 0x80, 0x56, 0x74, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xc0, 0xa8, 0x00, 0x95, 0xc0, 0xa8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xc0, 0xde, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
            0x00, 0x00, 0x78, 0x3a, 0x04, 0x00, 0x00, 0x00, 0x3c, 0x3b, 0x04, 0x00, 0x00, 0x00,
            0x69, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x1c, 0x04, 0xc0, 0xa8, 0x00, 0xff, 0x06,
            0x04, 0xc0, 0xa8, 0x00, 0x01, 0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }
}
