#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::options::{option_builder, DhcpOption},
    v6::*,
};

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
    /*LeaseQueryDone(Message),
    LeaseQueryData(Message),
    ReconfigureRequest(Message),
    ReconfigureReply(Message),
    DHCPv4Query(Message),
    DHCPv4Response(Message),*/
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
            /*LeaseQueryDone(_) => MessageType::Message,
            LeaseQueryData(_) => MessageType::Message,
            ReconfigureRequest(_) => MessageType::Message,
            ReconfigureReply(_) => MessageType::Message,
            DHCPv4Query(_) => MessageType::Message,
            DHCPv4Response(_) => MessageType::Message,*/
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
            /*LeaseQueryDone(message) => message.encode(e),
            LeaseQueryData(message) => message.encode(e),
            ReconfigureRequest(message) => message.encode(e),
            ReconfigureReply(message) => message.encode(e),
            DHCPv4Query(message) => message.encode(e),
            DHCPv4Response(message) => message.encode(e),*/
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
            /*MessageType::LeaseQueryDone => Message::LeaseQueryDone(Message::decode(decoder)?),
            MessageType::LeaseQueryData => Message::LeaseQueryData(Message::decode(decoder)?),
            MessageType::ReconfigureRequest => Message::ReconfigureRequest(Message::decode(decoder)?),
            MessageType::ReconfigureReply => Message::ReconfigureReply(Message::decode(decoder)?),
            MessageType::DHCPv4Query => Message::DHCPv4Query(Message::decode(decoder)?),
            MessageType::DHCPv4Response => Message::DHCPv4Response(Message::decode(decoder)?),*/
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
    DhcpOption,
    RelayMsg,
    VendorOpts,
    InterfaceId
);

option_builder!(
    SolicitOption,
    SolicitOptions,
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
    DhcpOption,
    ClientId,
    ServerId,
    Auth,
    ReconfMsg
);

option_builder!(
    InformationRequestOption,
    InformationRequestOptions,
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

option_builder!(LeaseQueryOption, LeaseQueryOptions, DhcpOption, LqQuery);

option_builder!(
    LeaseQueryReplyOption,
    LeaseQueryReplyOptions,
    DhcpOption,
    ClientData,
    LqRelayData,
    LqClientLink
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
    ($name: ident, $options: ident) => {
        impl From<$name> for Message {
            fn from(message: $name) -> Message {
                Message::$name(message)
            }
        }

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
    ($name: ident, $options: ident) => {
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

        base_message_builder!($name, $options);

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
    ($name: ident, $options: ident) => {
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub hop_count: u8,
            pub link_address: Ipv6Addr,
            pub peer_address: Ipv6Addr,
            pub opts: $options,
        }

        base_message_builder!($name, $options);

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

client_server_message_builder!(Solicit, SolicitOptions);
client_server_message_builder!(Advertise, AdvertiseOptions);
client_server_message_builder!(Request, RequestOptions);
client_server_message_builder!(Confirm, ConfirmOptions);
client_server_message_builder!(Renew, RenewOptions);
client_server_message_builder!(Rebind, RebindOptions);
client_server_message_builder!(Reply, ReplyOptions);
client_server_message_builder!(Decline, DeclineOptions);
client_server_message_builder!(Release, ReleaseOptions);
client_server_message_builder!(Reconfigure, ReconfigureOptions);
client_server_message_builder!(InformationRequest, InformationRequestOptions);

relay_message_builder!(RelayForw, RelayMessageOptions);
relay_message_builder!(RelayRepl, RelayMessageOptions);

client_server_message_builder!(LeaseQuery, LeaseQueryOptions);
client_server_message_builder!(LeaseQueryReply, LeaseQueryReplyOptions);
