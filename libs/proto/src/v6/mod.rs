//! DHCPv6 Message type
mod options;

// re-export submodules from proto::msg
pub use self::options::*;

pub use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::*,
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// message type
    /// https://datatracker.ietf.org/doc/html/rfc8415#section-7.3
    msg_type: MessageType,
    /// transaction id
    /// trns id must be the same for all messages in a DHCP transaction
    /// https://datatracker.ietf.org/doc/html/rfc8415#section-16.1
    xid: [u8; 3],
    /// Options
    /// https://datatracker.ietf.org/doc/html/rfc8415#section-21
    opts: DhcpOptions,
}

impl Message {
    /// Get the message's message type.
    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    /// Get the message's transaction id.
    pub fn transaction_id(&self) -> [u8; 3] {
        self.xid
    }

    /// Get a reference to the message's options.
    pub fn opts(&self) -> &DhcpOptions {
        &self.opts
    }

    /// Get a mutable reference to the message's options.
    pub fn opts_mut(&mut self) -> &mut DhcpOptions {
        &mut self.opts
    }

    pub fn to_vec(&self) -> EncodeResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(512);
        self.encode(&mut Encoder::new(&mut buffer))?;
        Ok(buffer)
    }
}

/// DHCPv6 message types
/// https://datatracker.ietf.org/doc/html/rfc8415#section-7.3
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    // RFC 3315
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InformationRequest,
    RelayForw,
    RelayRepl,
    // RFC 5007
    LeaseQuery,
    LeaseQueryReply,
    // RFC 5460
    LeaseQueryDone,
    LeaseQueryData,
    // RFC 6977
    ReconfigureRequest,
    ReconfigureReply,
    // RFC 7341
    DHCPv4Query,
    DHCPv4Response,
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

impl<'r> Decodable<'r> for Message {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(Message {
            msg_type: decoder.read_u8()?.into(),
            xid: decoder.read::<3>()?,
            opts: DhcpOptions::decode(decoder)?,
        })
    }
}

impl<'a> Encodable<'a> for Message {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<()> {
        e.write_u8(self.msg_type.into())?;
        e.write(self.xid)?;
        self.opts.encode(e)?;
        Ok(())
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
        assert_eq!(buf, input);
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
