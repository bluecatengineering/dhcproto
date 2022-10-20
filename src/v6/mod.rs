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
//! let duid = v6::Duid::from(vec![
//!     29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
//! ]);
//! // construct a new Solicit Message with a random xid
//! let mut msg = v6::Solicit::new();
//! // set an option
//! msg.opts_mut()
//!     .insert(v6::ClientId{id: duid});
//!
//! //access an option
//! let _id = msg.opts().get::<v6::ClientId>();
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
mod duid;
mod option_codes;
pub mod options;
///options
pub use options::{
    Auth, ClientData, ClientId, CltTime, DNSServers, DomainList, ElapsedTime, IAAddr, IAPrefix,
    InfMaxRt, InformationRefreshTime, InterfaceId, LinkAddress, LqClientLink, LqQuery, LqRelayData,
    Preference, RapidCommit, ReconfAccept, ReconfMsg, RelayId, RelayMsg, ServerId, SolMaxRt,
    StatusCode, Unicast, UserClass, VendorClass, VendorOpts, IANA, IAPD, IATA, ORO,
};
pub mod messages;
mod oro_codes;
///messages
pub use messages::{
    Advertise, BulkLeaseQueryMessage, Confirm, Decline, InformationRequest, LeaseQuery,
    LeaseQueryData, LeaseQueryDone, LeaseQueryReply, Message, Rebind, Reconfigure, RelayForw,
    RelayRepl, Release, Renew, Reply, Request, Solicit,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::{convert::TryInto, net::Ipv6Addr};

// re-export submodules from proto::msg
pub use self::duid::*;
pub use self::option_codes::*;
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

#[cfg(test)]
mod tests {

    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn decode_ipv6(input: Vec<u8>, mtype: MessageType) -> Result<()> {
        // decode
        let msg = Message::decode(&mut Decoder::new(&input))?;
        dbg!(&msg);
        assert_eq!(mtype, msg.msg_type());
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
        let msg = Solicit::default();
        let other_msg = Reply::new_with_xid(msg.xid);

        assert_eq!(msg.xid, other_msg.xid);
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
