#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::options::{option_builder, DhcpOption},
    v6::*,
};

///Bulk lease query messages for use over TCP
///Note: The u16 message-size from the start of the TCP message is not read or written, and only a buffer containing a one complete message will decode correctly.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkLeaseQueryMessage {
    LeaseQuery(LeaseQuery),
    LeaseQueryReply(LeaseQueryReply),
    LeaseQueryDone(LeaseQueryDone),
    LeaseQueryData(LeaseQueryData),
    Unknown(Vec<u8>),
}

impl BulkLeaseQueryMessage {
    pub fn msg_type(&self) -> MessageType {
        use BulkLeaseQueryMessage::*;
        match self {
            LeaseQuery(_) => MessageType::LeaseQuery,
            LeaseQueryReply(_) => MessageType::LeaseQueryReply,
            LeaseQueryDone(_) => MessageType::LeaseQueryDone,
            LeaseQueryData(_) => MessageType::LeaseQueryData,
            Unknown(v) => MessageType::Unknown(v[0]),
        }
    }
}

impl Encodable for BulkLeaseQueryMessage {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        use BulkLeaseQueryMessage::*;
        match self {
            LeaseQuery(message) => message.encode(e),
            LeaseQueryReply(message) => message.encode(e),
            LeaseQueryDone(message) => message.encode(e),
            LeaseQueryData(message) => message.encode(e),
            Unknown(message) => e.write_slice(message),
        }
    }
}

impl Decodable for BulkLeaseQueryMessage {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(match MessageType::from(decoder.peek_u8()?) {
            MessageType::LeaseQuery => {
                BulkLeaseQueryMessage::LeaseQuery(LeaseQuery::decode(decoder)?)
            }
            MessageType::LeaseQueryReply => {
                BulkLeaseQueryMessage::LeaseQueryReply(LeaseQueryReply::decode(decoder)?)
            }
            MessageType::LeaseQueryDone => {
                BulkLeaseQueryMessage::LeaseQueryDone(LeaseQueryDone::decode(decoder)?)
            }
            MessageType::LeaseQueryData => {
                BulkLeaseQueryMessage::LeaseQueryData(LeaseQueryData::decode(decoder)?)
            }
            _ => BulkLeaseQueryMessage::Unknown({
                let mut buf = vec![];
                while let Ok(b) = decoder.read_u8() {
                    buf.push(b);
                }
                buf
            }),
        })
    }
}

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

///Dhcp messages for use over UDP
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Solicit(Solicit),
    Advertise(Advertise),
    Request(Request),
    Confirm(Confirm),
    Renew(Renew),
    Rebind(Rebind),
    Reply(Reply),
    Release(Release),
    Decline(Decline),
    Reconfigure(Reconfigure),
    InformationRequest(InformationRequest),
    RelayForw(RelayForw),
    RelayRepl(RelayRepl),
    LeaseQuery(LeaseQuery),
    LeaseQueryReply(LeaseQueryReply),
    /*
    ReconfigureRequest(ReconfigureRequest),
    ReconfigureReply(ReconfigureReply),
    DHCPv4Query(DHCPv4Query),
    DHCPv4Response(DHCPv4Response),
     */
    Unknown(Vec<u8>),
}

impl Message {
    pub fn msg_type(&self) -> MessageType {
        use Message::*;
        match self {
            Solicit(_) => MessageType::Solicit,
            Advertise(_) => MessageType::Advertise,
            Request(_) => MessageType::Request,
            Confirm(_) => MessageType::Confirm,
            Renew(_) => MessageType::Renew,
            Rebind(_) => MessageType::Rebind,
            Reply(_) => MessageType::Reply,
            Release(_) => MessageType::Release,
            Decline(_) => MessageType::Decline,
            Reconfigure(_) => MessageType::Reconfigure,
            InformationRequest(_) => MessageType::InformationRequest,
            RelayForw(_) => MessageType::RelayForw,
            RelayRepl(_) => MessageType::RelayRepl,
            LeaseQuery(_) => MessageType::LeaseQuery,
            LeaseQueryReply(_) => MessageType::LeaseQueryReply,
            /*
            ReconfigureRequest(_) => MessageType::ReconfigureRequest,
            ReconfigureReply(_) => MessageType::ReconfigureReply,
            DHCPv4Query(_) => MessageType::ReconfigureReply,
            DHCPv4Response(_) => MessageType::ReconfigureReply,
             */
            Unknown(v) => MessageType::Unknown(v[0]),
        }
    }
}

impl Encodable for Message {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        use Message::*;
        match self {
            Solicit(message) => message.encode(e),
            Advertise(message) => message.encode(e),
            Request(message) => message.encode(e),
            Confirm(message) => message.encode(e),
            Renew(message) => message.encode(e),
            Rebind(message) => message.encode(e),
            Reply(message) => message.encode(e),
            Release(message) => message.encode(e),
            Decline(message) => message.encode(e),
            Reconfigure(message) => message.encode(e),
            InformationRequest(message) => message.encode(e),
            RelayForw(message) => message.encode(e),
            RelayRepl(message) => message.encode(e),
            LeaseQuery(message) => message.encode(e),
            LeaseQueryReply(message) => message.encode(e),
            /*
            ReconfigureRequest(message) => message.encode(e),
            ReconfigureReply(message) => message.encode(e),
            DHCPv4Query(message) => message.encode(e),
            DHCPv4Response(message) => message.encode(e),
             */
            Unknown(message) => e.write_slice(message),
        }
    }
}

impl Decodable for Message {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(match MessageType::from(decoder.peek_u8()?) {
            MessageType::Solicit => Message::Solicit(Solicit::decode(decoder)?),
            MessageType::Advertise => Message::Advertise(Advertise::decode(decoder)?),
            MessageType::Request => Message::Request(Request::decode(decoder)?),
            MessageType::Confirm => Message::Confirm(Confirm::decode(decoder)?),
            MessageType::Renew => Message::Renew(Renew::decode(decoder)?),
            MessageType::Rebind => Message::Rebind(Rebind::decode(decoder)?),
            MessageType::Reply => Message::Reply(Reply::decode(decoder)?),
            MessageType::Release => Message::Release(Release::decode(decoder)?),
            MessageType::Decline => Message::Decline(Decline::decode(decoder)?),
            MessageType::Reconfigure => Message::Reconfigure(Reconfigure::decode(decoder)?),
            MessageType::InformationRequest => {
                Message::InformationRequest(InformationRequest::decode(decoder)?)
            }
            MessageType::RelayForw => Message::RelayForw(RelayForw::decode(decoder)?),
            MessageType::RelayRepl => Message::RelayRepl(RelayRepl::decode(decoder)?),
            MessageType::LeaseQuery => Message::LeaseQuery(LeaseQuery::decode(decoder)?),
            MessageType::LeaseQueryReply => {
                Message::LeaseQueryReply(LeaseQueryReply::decode(decoder)?)
            }
            /*
            MessageType::ReconfigureRequest => Message::ReconfigureRequest(ReconfigureRequest::decode(decoder)?),
            MessageType::ReconfigureReply => Message::ReconfigureReply(ReconfigureReply::decode(decoder)?),
            MessageType::DHCPv4Query => Message::DHCPv4Query(DHCPv4Query::decode(decoder)?),
            MessageType::DHCPv4Response => Message::DHCPv4Response(DHCPv4Response::decode(decoder)?),
            */
            _ => Message::Unknown({
                let mut buf = vec![];
                while let Ok(b) = decoder.read_u8() {
                    buf.push(b);
                }
                buf
            }),
        })
    }
}

option_builder!(
    MessageOption,
    MessageOptions,
    IsMessageOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAAddr,
    IAPD,
    IAPrefix,
    ORO,
    Preference,
    ElapsedTime,
    Auth,
    Unicast,
    StatusCode,
    RapidCommit,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfMsg,
    ReconfAccept,
    InformationRefreshTime,
    SolMaxRt,
    InfMaxRt,
    DNSServers,
    DomainList
);

option_builder!(
    RelayMessageOption,
    RelayMessageOptions,
    IsRelayMessageOption,
    DhcpOption,
    RelayMsg,
    VendorOpts,
    InterfaceId
);

option_builder!(
    SolicitOption,
    SolicitOptions,
    IsSolicitOption,
    DhcpOption,
    ClientId,
    IANA,
    IATA,
    IAPD,
    ORO,
    ElapsedTime,
    RapidCommit,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept
);

option_builder!(
    AdvertiseOption,
    AdvertiseOptions,
    IsAdvertiseOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    Preference,
    StatusCode,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept,
    SolMaxRt
);

option_builder!(
    RequestOption,
    RequestOptions,
    IsRequestOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept
);

option_builder!(
    ConfirmOption,
    ConfirmOptions,
    IsConfirmOption,
    DhcpOption,
    ClientId,
    IANA,
    IATA,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts
);

option_builder!(
    RenewOption,
    RenewOptions,
    IsRenewOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    ORO,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept
);

option_builder!(
    RebindOption,
    RebindOptions,
    IsRebindOption,
    DhcpOption,
    ClientId,
    IANA,
    IATA,
    IAPD,
    ORO,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept
);

option_builder!(
    DeclineOption,
    DeclineOptions,
    IsDeclineOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts
);

option_builder!(
    ReleaseOption,
    ReleaseOptions,
    IsReleaseOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts
);

option_builder!(
    ReplyOption,
    ReplyOptions,
    IsReplyOption,
    DhcpOption,
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    Auth,
    Unicast,
    StatusCode,
    RapidCommit,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept,
    InformationRefreshTime,
    SolMaxRt,
    InfMaxRt
);

option_builder!(
    ReconfigureOption,
    ReconfigureOptions,
    IsReconfigureOption,
    DhcpOption,
    ClientId,
    ServerId,
    Auth,
    ReconfMsg
);

option_builder!(
    InformationRequestOption,
    InformationRequestOptions,
    IsInformationRequestOption,
    DhcpOption,
    ClientId,
    ServerId,
    ORO,
    ElapsedTime,
    UserClass,
    VendorClass,
    VendorOpts,
    ReconfAccept
);

option_builder!(
    LeaseQueryOption,
    LeaseQueryOptions,
    IsLeaseQueryOption,
    DhcpOption,
    LqQuery
);

option_builder!(
    LeaseQueryReplyOption,
    LeaseQueryReplyOptions,
    IsLeaseQueryReplyOption,
    DhcpOption,
    ClientData,
    LqRelayData,
    LqClientLink
);

//TODO: work out which options are alloud in LeaseQueryData message
option_builder!(
    LeaseQueryDataOption,
    LeaseQueryDataOptions,
    IsLeaseQueryDataOption,
    DhcpOption,
);
//TODO: work out which options are alloud in LeaseQueryDone message
option_builder!(
    LeaseQueryDoneOption,
    LeaseQueryDoneOptions,
    IsLeaseQueryDoneOption,
    DhcpOption,
);

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TransactionId {
    pub id: [u8; 3],
}

impl Default for TransactionId {
    fn default() -> Self {
        Self { id: rand::random() }
    }
}

impl Encodable for TransactionId {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_slice(&self.id)?;
        Ok(())
    }
}

impl Decodable for TransactionId {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(TransactionId {
            id: decoder.read::<3>()?,
        })
    }
}

macro_rules! base_message_builder {
    ($name: ident, $options: ident, $($messagetype: ident),*) => {
		$(
        impl From<$name> for $messagetype {
            fn from(message: $name) -> $messagetype {
                $messagetype::$name(message)
            }
        }
		)*

        impl $name {
            /// Get a reference to the message's options.
            pub fn opts(&self) -> &$options {
                &self.opts
            }
            /// Get a mutable reference to the message's options.
            pub fn opts_mut(&mut self) -> &mut $options {
                &mut self.opts
            }
        }
    };
}

macro_rules! client_server_message_builder {
    ($name: ident, $options: ident, $($messagetype: ident),*) => {
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            pub xid: TransactionId,
            pub opts: $options,
        }

        impl $name {
            /// returns a new `Message` with a random xid and empty opt section
            pub fn new() -> Self {
                Self::default()
            }
            /// returns a new `Message` with an empty opt section
            pub fn new_with_xid<T: Into<TransactionId>>(xid: T) -> Self {
                Self {
                    xid: xid.into(),
                    ..Self::default()
                }
            }
        }

        base_message_builder!($name, $options, $($messagetype),*);

        impl Encodable for $name {
            fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
                e.write_u8(MessageType::$name.into())?;
                self.xid.encode(e)?;
                self.opts.encode(e)?;
                Ok(())
            }
        }

        impl Decodable for $name {
            fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
                let _message_type = decoder.read_u8()?;
                Ok(Self {
                    xid: TransactionId::decode(decoder)?,
                    opts: $options::decode(decoder)?,
                })
            }
        }
    };
}

macro_rules! relay_message_builder {
    ($name: ident, $options: ident, $($messagetype: ident),*) => {
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub hop_count: u8,
            pub link_address: Ipv6Addr,
            pub peer_address: Ipv6Addr,
            pub opts: $options,
        }

        base_message_builder!($name, $options, $($messagetype)*);

        impl Encodable for $name {
            fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
                e.write_u8(MessageType::$name.into())?;
                e.write_u8(self.hop_count)?;
                e.write::<16>(self.link_address.octets())?;
                e.write::<16>(self.peer_address.octets())?;
                self.opts.encode(e)?;
                Ok(())
            }
        }

        impl Decodable for $name {
            fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
                let _message_type = decoder.read_u8()?;
                Ok(Self {
                    hop_count: decoder.read_u8()?,
                    link_address: decoder.read::<16>()?.into(),
                    peer_address: decoder.read::<16>()?.into(),
                    opts: $options::decode(decoder)?,
                })
            }
        }
    };
}

/*macro_rules! dhcp4o6_message_builder {
     ($name: ident, $options: ident, $($messagetype: ident),*) => {
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub flags: [u8;3],
            pub opts: $options,
        }

        base_message_builder!($name, $options, $($messagetype)*);

        impl Encodable for $name {
            fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
                e.write_u8(MessageType::$name.into())?;
                e.write_slice(self.flags)?;
                self.opts.encode(e)?;
                Ok(())
            }
        }

        impl Decodable for $name {
            fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
                let _message_type = decoder.read_u8()?;
                Ok(Self {
                    flags: decoder.read::<3>()?,
                    opts: $options::decode(decoder)?,
                })
            }
        }
    };
}*/

client_server_message_builder!(Solicit, SolicitOptions, Message);
client_server_message_builder!(Advertise, AdvertiseOptions, Message);
client_server_message_builder!(Request, RequestOptions, Message);
client_server_message_builder!(Confirm, ConfirmOptions, Message);
client_server_message_builder!(Renew, RenewOptions, Message);
client_server_message_builder!(Rebind, RebindOptions, Message);
client_server_message_builder!(Reply, ReplyOptions, Message);
client_server_message_builder!(Decline, DeclineOptions, Message);
client_server_message_builder!(Release, ReleaseOptions, Message);
client_server_message_builder!(Reconfigure, ReconfigureOptions, Message);
client_server_message_builder!(InformationRequest, InformationRequestOptions, Message);

relay_message_builder!(RelayForw, RelayMessageOptions, Message);
relay_message_builder!(RelayRepl, RelayMessageOptions, Message);

client_server_message_builder!(
    LeaseQuery,
    LeaseQueryOptions,
    Message,
    BulkLeaseQueryMessage
);
client_server_message_builder!(
    LeaseQueryReply,
    LeaseQueryReplyOptions,
    Message,
    BulkLeaseQueryMessage
);

client_server_message_builder!(LeaseQueryData, LeaseQueryDataOptions, BulkLeaseQueryMessage);
client_server_message_builder!(LeaseQueryDone, LeaseQueryDoneOptions, BulkLeaseQueryMessage);
