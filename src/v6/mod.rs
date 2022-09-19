//! # DHCPv6
//!
//! This module provides types and utility functions for encoding/decoding a DHCPv4 message.
//!
//! ## Example - constructing messages
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use dhcproto::{v6, Encodable, Encoder};
//! // arbitrary DUID
//! let duid = vec![
//!     29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
//! ];
//! // construct a new Message with a random xid
//! let mut msg = v6::Message::new(v6::MessageType::Solicit);
//! // set an option
//! msg.opts_mut()
//!     .insert(v6::DhcpOption::ClientId(duid));
//!
//! // now encode to bytes
//! let mut buf = Vec::new();
//! let mut e = Encoder::new(&mut buf);
//! msg.encode(&mut e)?;
//!
//! // buf now has the contents of the encoded DHCP message
//! # Ok(()) }
//! ```
//!
//! ## Example - encoding/decoding messages
//!
//! ```rust
//! # fn solicit() -> Vec<u8> {
//! #     vec![
//! #         0x01, 0x10, 0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39,
//! #         0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17,
//! #         0x00, 0x18, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe,
//! #         0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x15, 0x18,
//! #     ]
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use dhcproto::{v6::Message, Decoder, Decodable, Encoder, Encodable};
//! // example message
//! let solicit = solicit();
//! // decode
//! let msg = Message::decode(&mut Decoder::new(&solicit))?;
//! // now encode
//! let mut buf = Vec::new();
//! let mut e = Encoder::new(&mut buf);
//! msg.encode(&mut e)?;
//!
//! assert_eq!(solicit, buf);
//! # Ok(()) }
//! ```
//!
mod options;
mod oro_codes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::{convert::TryInto, fmt, net::Ipv6Addr};

// re-export submodules from proto::msg
pub use self::options::*;
pub use self::oro_codes::*;

pub use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::*,
};

/// default dhcpv6 server port
pub const SERVER_PORT: u16 = 547;
/// default dhcpv6 client port
pub const CLIENT_PORT: u16 = 546;

/// See RFC 8415 for updated DHCPv6 info
/// [DHCP for Ipv6](https://datatracker.ietf.org/doc/html/rfc8415)
///
///   All DHCP messages sent between clients and servers share an identical
///   fixed-format header and a variable-format area for options.
///
///   All values in the message header and in options are in network byte
///   order.
///
///   Options are stored serially in the "options" field, with no padding
///   between the options.  Options are byte-aligned but are not aligned in
///   any other way (such as on 2-byte or 4-byte boundaries).
///
///   The following diagram illustrates the format of DHCP messages sent
///   between clients and servers:
///
/// ```text
///       0                   1                   2                   3
///       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |    msg-type   |               transaction-id                  |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///      |                                                               |
///      .                            options                            .
///      .                 (variable number and length)                  .
///      |                                                               |
///      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///      msg-type             Identifies the DHCP message type; the
///                           available message types are listed in
///                           Section 7.3.  A 1-octet field.
///
///      transaction-id       The transaction ID for this message exchange.
///                           A 3-octet field.
///
///      options              Options carried in this message; options are
///                           described in Section 21.  A variable-length
///                           field (4 octets less than the size of the
///                           message).
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// message type
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    msg_type: MessageType,
    /// transaction id
    /// trns id must be the same for all messages in a DHCP transaction
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-16.1>
    xid: [u8; 3],
    /// Options
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-21>
    opts: DhcpOptions,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            msg_type: MessageType::Solicit,
            xid: rand::random(),
            opts: DhcpOptions::new(),
        }
    }
}

impl Message {
    /// returns a new `Message` with a random xid and empty opt section
    pub fn new(msg_type: MessageType) -> Self {
        Self {
            msg_type,
            ..Self::default()
        }
    }

    /// returns a new `Message` with a given xid and message type and empty opt section
    pub fn new_with_id(msg_type: MessageType, xid: [u8; 3]) -> Self {
        Self {
            msg_type,
            xid,
            ..Self::default()
        }
    }

    /// Get the message's message type.
    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    /// Set message type
    pub fn set_msg_type(&mut self, msg_type: MessageType) -> &mut Self {
        self.msg_type = msg_type;
        self
    }

    /// Get the message's transaction id.
    pub fn xid(&self) -> [u8; 3] {
        self.xid
    }

    /// Get the msgs transaction id as a number
    pub fn xid_num(&self) -> u32 {
        u32::from_be_bytes([0, self.xid[0], self.xid[1], self.xid[2]])
    }

    /// Set transaction id
    pub fn set_xid(&mut self, xid: [u8; 3]) -> &mut Self {
        self.xid = xid;
        self
    }

    /// Set transaction id from u32, will only use last 3 bytes
    pub fn set_xid_num(&mut self, xid: u32) -> &mut Self {
        let arr = xid.to_be_bytes();
        self.xid = arr[1..=3]
            .try_into()
            .expect("a u32 has 4 bytes so this shouldn't fail");
        self
    }

    /// Get a reference to the message's options.
    pub fn opts(&self) -> &DhcpOptions {
        &self.opts
    }

    /// Set DHCP opts
    pub fn set_opts(&mut self, opts: DhcpOptions) -> &mut Self {
        self.opts = opts;
        self
    }

    /// Get a mutable reference to the message's options.
    pub fn opts_mut(&mut self) -> &mut DhcpOptions {
        &mut self.opts
    }
}

/// DHCPv6 message types
/// <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    // RFC 3315
    /// client solicit - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Solicit,
    /// server advertise - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Advertise,
    /// request - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Request,
    /// confirm - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Confirm,
    /// renew - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Renew,
    /// rebind - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Rebind,
    /// reply - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Reply,
    /// release message type - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Release,
    /// decline - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Decline,
    /// reconfigure - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    Reconfigure,
    /// information request - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    InformationRequest,
    /// relay forward - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    RelayForw,
    /// relay reply - <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    RelayRepl,
    // RFC 5007
    /// lease query - <https://datatracker.ietf.org/doc/html/rfc5007#section-4.2.1>
    LeaseQuery,
    /// lease query reply - <https://datatracker.ietf.org/doc/html/rfc5007#section-4.2.2>
    LeaseQueryReply,
    // RFC 5460
    /// lease query done - <https://datatracker.ietf.org/doc/html/rfc5460#section-5.2.2>
    LeaseQueryDone,
    /// lease query data - <https://datatracker.ietf.org/doc/html/rfc5460#section-5.2.1>
    LeaseQueryData,
    // RFC 6977
    /// reconfigure request - <https://datatracker.ietf.org/doc/html/rfc6977#section-6.2.1>
    ReconfigureRequest,
    /// reconfigure reply - <https://datatracker.ietf.org/doc/html/rfc6977#section-6.2.2>
    ReconfigureReply,
    // RFC 7341
    /// dhcpv4 query - <https://datatracker.ietf.org/doc/html/rfc7341#section-6.2>
    DHCPv4Query,
    /// dhcpv4 response - <https://datatracker.ietf.org/doc/html/rfc7341#section-6.2>
    DHCPv4Response,
    /// unknown/unimplemented message type
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(n: u8) -> Self {
        use MessageType::*;
        match n {
            // RFC 3315
            1 => Solicit,
            2 => Advertise,
            3 => Request,
            4 => Confirm,
            5 => Renew,
            6 => Rebind,
            7 => Reply,
            8 => Release,
            9 => Decline,
            10 => Reconfigure,
            11 => InformationRequest,
            12 => RelayForw,
            13 => RelayRepl,
            // RFC 5007
            14 => LeaseQuery,
            15 => LeaseQueryReply,
            // RFC 5460
            16 => LeaseQueryDone,
            17 => LeaseQueryData,
            // RFC 6977
            18 => ReconfigureRequest,
            19 => ReconfigureReply,
            // RFC 7341
            20 => DHCPv4Query,
            21 => DHCPv4Response,
            n => Unknown(n),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(m: MessageType) -> Self {
        use MessageType::*;
        match m {
            // RFC 3315
            Solicit => 1,
            Advertise => 2,
            Request => 3,
            Confirm => 4,
            Renew => 5,
            Rebind => 6,
            Reply => 7,
            Release => 8,
            Decline => 9,
            Reconfigure => 10,
            InformationRequest => 11,
            RelayForw => 12,
            RelayRepl => 13,
            // RFC 5007
            LeaseQuery => 14,
            LeaseQueryReply => 15,
            // RFC 5460
            LeaseQueryDone => 16,
            LeaseQueryData => 17,
            // RFC 6977
            ReconfigureRequest => 18,
            ReconfigureReply => 19,
            // RFC 7341
            DHCPv4Query => 20,
            DHCPv4Response => 21,
            Unknown(n) => n,
        }
    }
}

impl Decodable for Message {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(Message {
            msg_type: decoder.read_u8()?.into(),
            xid: decoder.read::<3>()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

impl Encodable for Message {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u8(self.msg_type.into())?;
        e.write(self.xid)?;
        self.opts.encode(e)?;
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("xid", &self.xid_num())
            .field("msg_type", &self.msg_type())
            .field("opts", &self.opts())
            .finish()
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    /// message type
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-7.3>
    msg_type: MessageType,
    /// hop count
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-9>
    hop_count: u8,
    /// link address
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-9>
    link_addr: Ipv6Addr,
    /// peer address
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-9>
    peer_addr: Ipv6Addr,
    /// Options
    /// <https://datatracker.ietf.org/doc/html/rfc8415#section-21>
    opts: DhcpOptions,
}

impl RelayMessage {
    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
    pub fn hop_count(&self) -> u8 {
        self.hop_count
    }
    pub fn link_addr(&self) -> Ipv6Addr {
        self.link_addr
    }
    pub fn peer_addr(&self) -> Ipv6Addr {
        self.peer_addr
    }
    /// Get a reference to the message's options.
    pub fn opts(&self) -> &DhcpOptions {
        &self.opts
    }

    /// Set DHCP opts
    pub fn set_opts(&mut self, opts: DhcpOptions) -> &mut Self {
        self.opts = opts;
        self
    }

    /// Get a mutable reference to the message's options.
    pub fn opts_mut(&mut self) -> &mut DhcpOptions {
        &mut self.opts
    }
}

impl Decodable for RelayMessage {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(Self {
            msg_type: decoder.read_u8()?.into(),
            hop_count: decoder.read_u8()?,
            link_addr: decoder.read::<16>()?.into(),
            peer_addr: decoder.read::<16>()?.into(),
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

impl Encodable for RelayMessage {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u8(self.msg_type.into())?;
        e.write_u8(self.hop_count)?;
        e.write_slice(&self.link_addr.octets())?;
        e.write_slice(&self.peer_addr.octets())?;
        self.opts.encode(e)?;
        Ok(())
    }
}

impl fmt::Display for RelayMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayMessage")
            .field("msg_type", &self.msg_type())
            .field("hop_count", &self.hop_count())
            .field("link_addr", &self.link_addr())
            .field("peer_addr", &self.peer_addr())
            .field("opts", &self.opts())
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn decode_ipv6(input: Vec<u8>, mtype: MessageType) -> Result<()> {
        // decode
        let msg = Message::decode(&mut Decoder::new(&input))?;
        dbg!(&msg);
        assert_eq!(mtype, msg.msg_type);
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        println!("{:?}", buf);
        println!("{:?}", input);
        // no PAD bytes or hashmap with ipv6 so the lens will be exact
        assert_eq!(buf.len(), input.len());
        // decode again
        let res = Message::decode(&mut Decoder::new(&buf))?;
        // check Messages are equal after decoding/encoding
        assert_eq!(msg, res);
        Ok(())
    }

    #[test]
    fn decode_solicit() -> Result<()> {
        decode_ipv6(solicit(), MessageType::Solicit)?;
        Ok(())
    }

    #[test]
    fn decode_advertise() -> Result<()> {
        decode_ipv6(advertise(), MessageType::Advertise)?;
        Ok(())
    }

    #[test]
    fn decode_request() -> Result<()> {
        decode_ipv6(request(), MessageType::Request)?;
        Ok(())
    }

    #[test]
    fn decode_reply() -> Result<()> {
        decode_ipv6(reply(), MessageType::Reply)?;
        Ok(())
    }

    #[test]
    fn xid_num() {
        let mut msg = Message::default();
        msg.set_xid_num(16_777_215);
        assert_eq!(msg.xid_num(), 16_777_215);

        msg.set_xid_num(16_777_000);
        assert_eq!(msg.xid_num(), 16_777_000);

        msg.set_xid_num(8);
        assert_eq!(msg.xid_num(), 8);
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_json_v6() -> Result<()> {
        let msg = Message::decode(&mut Decoder::new(&solicit()))?;
        let s = serde_json::to_string_pretty(&msg)?;
        println!("{s}");
        let other = serde_json::from_str(&s)?;
        assert_eq!(msg, other);
        Ok(())
    }

    fn solicit() -> Vec<u8> {
        vec![
            0x01, 0x10, 0x08, 0x74, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39,
            0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17,
            0x00, 0x18, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0c, 0x27, 0xfe,
            0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x15, 0x18,
        ]
    }

    fn advertise() -> Vec<u8> {
        vec![
            0x02, 0x10, 0x08, 0x74, 0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x11, 0x94,
            0x00, 0x00, 0x1c, 0x20, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00,
            0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00,
            0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27, 0xd4, 0x10,
            0xbb,
        ]
    }

    fn request() -> Vec<u8> {
        vec![
            0x03, 0x49, 0x17, 0x4e, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39,
            0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01,
            0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27, 0xd4, 0x10, 0xbb, 0x00, 0x06,
            0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19,
            0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00, 0x15, 0x18,
            0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x1d, 0x4c, 0x40, 0x20,
            0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ]
    }

    fn reply() -> Vec<u8> {
        vec![
            0x07, 0x49, 0x17, 0x4e, 0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x11, 0x94,
            0x00, 0x00, 0x1c, 0x20, 0x40, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00,
            0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00,
            0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27, 0xd4, 0x10,
            0xbb,
        ]
    }
}
