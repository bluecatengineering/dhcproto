use std::{borrow::Cow, collections::HashMap, iter, net::Ipv4Addr};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v4::bulk_query,
    v4::{fqdn, relay},
};

use hickory_proto::{
    rr::Name,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, EncodeMode},
};
use ipnet::Ipv4Net;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// declares DHCP Option codes.
// generates:
// * the `OptionCode` enum and its From<u8>, Into<u8>
// * the DhcpOption enum
// * From<&DhcpOption> for OptionCode
//
// Syntax is {N, Name, "DocString" [,(T0,..TN,)]}
// where:
// * N is the numeric code associated with this option
// * Name is the name to use for the enum variants
// * "Docstring" is the documentation string that will be added to the variant in the OptionCode enum
// * (T0,..TN) is the associated variables (if any). e.g. Ipv4Addr for "SubnetMask" or bool for "IpForwarding".
//   can contain more than one type but needs to be enclosed in parenthesis even if it's just a single variable.
dhcproto_macros::declare_codes!(
    {0,   Pad, "Padding"},
    {1,   SubnetMask, "Subnet Mask", (Ipv4Addr)},
    {2,   TimeOffset, "Time Offset", (i32)},
    {3,   Router, "Router", (Vec<Ipv4Addr>)},
    {4,   TimeServer, "Router", (Vec<Ipv4Addr>)},
    {5,   NameServer, "Name Server", (Vec<Ipv4Addr>)},
    {6,   DomainNameServer, "Name Server", (Vec<Ipv4Addr>)},
    {7,   LogServer, "Log Server", (Vec<Ipv4Addr>)},
    {8,   QuoteServer, "Quote Server", (Vec<Ipv4Addr>)},
    {9,   LprServer, "LPR Server", (Vec<Ipv4Addr>)},
    {10,  ImpressServer, "Impress server", (Vec<Ipv4Addr>)},
    {11,  ResourceLocationServer, "Resource Location Server", (Vec<Ipv4Addr>)},
    {12,  Hostname, "Host name", (String)},
    {13,  BootFileSize, "Boot file size", (u16)},
    {14,  MeritDumpFile, "Merit Dump File", (String)},
    {15,  DomainName, "Domain Name", (String)},
    {16,  SwapServer, "Swap server", (Ipv4Addr)},
    {17,  RootPath, "Root Path", (String)},
    {18,  ExtensionsPath, "Extensions path", (String)},
    {19,  IpForwarding, "IP forwarding", (bool)},
    {20,  NonLocalSrcRouting, "Non-local source routing", (bool)},
    {21,  PolicyFilter, "Policy Filter", (Vec<(Ipv4Addr, Ipv4Addr)>)},
    {22,  MaxDatagramSize, "Max Datagram reassembly size", (u16)},
    {23,  DefaultIpTtl, "Ip TTL", (u8)},
    {24,  PathMtuAgingTimeout, "Path MTU Aging Timeout", (u32)},
    {25,  PathMtuPlateauTable, "Path MTU Plateau Table", (Vec<u16>)},
    {26,  InterfaceMtu, "Interface MTU", (u16)},
    {27,  AllSubnetsLocal, "All Subnets Local", (bool)},
    {28,  BroadcastAddr, "Broadcast address", (Ipv4Addr)},
    {29,  PerformMaskDiscovery, "Perform mask discovery", (bool)},
    {30,  MaskSupplier, "Mask supplier", (bool)},
    {31,  PerformRouterDiscovery, "Perform router discovery", (bool)},
    {32,  RouterSolicitationAddr, "Router solicitation address", (Ipv4Addr)},
    {33,  StaticRoutingTable, "Static routing table", (Vec<(Ipv4Addr, Ipv4Addr)>)},
    {34,  TrailerEncapsulated, "Trailer Encapsulated", (bool)},
    {35,  ArpCacheTimeout, "ARP timeout", (u32)},
    {36,  EthernetEncapsulation, "Ethernet encapsulation", (bool)},
    {37,  DefaultTcpTtl, "Default TCP TTL", (u8)},
    {38,  TcpKeepaliveInterval, "TCP keepalive interval", (u32)},
    {39,  TcpKeepaliveGarbage, "TCP keealive garbage", (bool)},
    {40,  NisDomain, "Network information service domain", (String)},
    {41,  NisServers, "NIS servers", (Vec<Ipv4Addr>)},
    {42,  NtpServers, "NTP servers", (Vec<Ipv4Addr>)},
    {43,  VendorExtensions, "Vendor Extensions - can contain encapsulated options", (Vec<u8>)}, // TODO: Hashmap<u8, UnknownOption>?
    {44,  NetBiosNameServers, "NetBIOS over TCP/IP name server", (Vec<Ipv4Addr>)},
    {45,  NetBiosDatagramDistributionServer, "NetBIOS over TCP/IP Datagram Distribution Server", (Vec<Ipv4Addr>)},
    {46,  NetBiosNodeType, "NetBIOS over TCP/IP Node Type", (NodeType)},
    {47,  NetBiosScope, "NetBIOS over TCP/IP Scope", (String)},
    {48,  XFontServer, "X Window System Font Server", (Vec<Ipv4Addr>)},
    {49,  XDisplayManager, "Window System Display Manager", (Vec<Ipv4Addr>)},
    {50,  RequestedIpAddress, "Requested IP Address", (Ipv4Addr)},
    {51,  AddressLeaseTime, "IP Address Lease Time", (u32)},
    {52,  OptionOverload, "Option Overload", (u8)},
    {53,  MessageType, "Message Type", (MessageType)},
    {54,  ServerIdentifier, "Server Identifier", (Ipv4Addr)},
    {55,  ParameterRequestList, "Parameter Request List", (Vec<OptionCode>)},
    {56,  Message, "Message", (String)},
    {57,  MaxMessageSize, "Maximum DHCP Message Size", (u16)},
    {58,  Renewal, "Renewal (T1) Time Value", (u32)},
    {59,  Rebinding, "Rebinding (T2) Time Value", (u32)},
    {60,  ClassIdentifier, "Class-identifier", (Vec<u8>)},
    {61,  ClientIdentifier, "Client Identifier", (Vec<u8>)},
    {62,  NwipDomainName, "Netware/IP Domain Name", (String)},
    {63,  NwipInformation, "Netware/IP Information - <https://www.rfc-editor.org/rfc/rfc2242.html>", (Vec<u8>)}, // TODO: https://www.rfc-editor.org/rfc/rfc2242.html sub opts
    {64,  NispServiceDomain, "NIS+ Domain Option", (String)},
    {65,  NispServers, "NIS+ Server Addr", (Vec<Ipv4Addr>)},
    {66,  TFTPServerName, "TFTP Server Name - <https://www.rfc-editor.org/rfc/rfc2132.html>", (Vec<u8>)},
    {67,  BootfileName, "Bootfile Name - <https://www.rfc-editor.org/rfc/rfc2132.html>", (Vec<u8>)},
    {68,  MobileIpHomeAgent, "Mobile IP Home Agent", (Vec<Ipv4Addr>)},
    {69,  SmtpServer, "SMTP Server Option", (Vec<Ipv4Addr>)},
    {70,  Pop3Server, "Pop3 Server Option", (Vec<Ipv4Addr>)},
    {71,  NntpServer, "NNTP Server Option", (Vec<Ipv4Addr>)},
    {72,  WwwServer, "WWW Server Option", (Vec<Ipv4Addr>)},
    {73,  DefaultFingerServer, "Default Finger Option", (Vec<Ipv4Addr>)},
    {74,  IrcServer, "IRC Server Option", (Vec<Ipv4Addr>)},
    {75,  StreetTalkServer, "StreetTalk Server Option", (Vec<Ipv4Addr>)},
    {76,  StreetTalkDirectoryAssistance, "StreetTalk Directory Insistance (STDA) Option", (Vec<Ipv4Addr>)},
    // TODO: split user-class into individual classes [len | <class>, ...]
    {77,  UserClass, "User Class Option - <https://www.rfc-editor.org/rfc/rfc3004.html>", (Vec<u8>)},
    {80,  RapidCommit, "Rapid Commit - <https://www.rfc-editor.org/rfc/rfc4039.html>"},
    {81,  ClientFQDN, "FQDN - <https://datatracker.ietf.org/doc/html/rfc4702>", (fqdn::ClientFQDN)},
    {82,  RelayAgentInformation, "Relay Agent Information - <https://datatracker.ietf.org/doc/html/rfc3046>", (relay::RelayAgentInformation)},
    {88,  BcmsControllerNames, "Broadcast Multicast Controller Names - <https://www.rfc-editor.org/rfc/rfc4280.html#section-4.1>", (Vec<Name>)},
    {89,  BcmsControllerAddrs, "Broadcast Mutlicast Controller Address - <https://www.rfc-editor.org/rfc/rfc4280.html#section-4.3>", (Vec<Ipv4Addr>)},
    {91,  ClientLastTransactionTime, "client-last-transaction-time - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>", (u32)},
    {92,  AssociatedIp, "associated-ip - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>", (Vec<Ipv4Addr>)},
    {93,  ClientSystemArchitecture, "Client System Architecture - <https://www.rfc-editor.org/rfc/rfc4578.html>", (Architecture)},
    {94,  ClientNetworkInterface, "Client Network Interface - <https://www.rfc-editor.org/rfc/rfc4578.html>", (u8, u8, u8)},
    {97,  ClientMachineIdentifier, "Client Machine Identifier - <https://www.rfc-editor.org/rfc/rfc4578.html>", (Vec<u8>)},
    {106, Ipv6OnlyPreferred, "IPv6-Only Preferred - <https://datatracker.ietf.org/doc/html/rfc8925>", (u32)},
    {114, CaptivePortal, "Captive Portal - <https://datatracker.ietf.org/doc/html/rfc8910>", (url::Url)},
    {116, DisableSLAAC, "Disable Stateless Autoconfig for Ipv4 - <https://datatracker.ietf.org/doc/html/rfc2563>", (AutoConfig)},
    {118, SubnetSelection, "Subnet selection - <https://datatracker.ietf.org/doc/html/rfc3011>", (Ipv4Addr)},
    {119, DomainSearch, "Domain Search - <https://www.rfc-editor.org/rfc/rfc3397.html>", (Vec<Name>)},
    {121, ClasslessStaticRoute, "Classless Static Route - <https://www.rfc-editor.org/rfc/rfc3442>", (Vec<(Ipv4Net, Ipv4Addr)>)},
    {150, TFTPServerAddress, "TFTP Server Address - <https://www.rfc-editor.org/rfc/rfc5859.html>", (Ipv4Addr)},
    {151, BulkLeaseQueryStatusCode, "BLQ status-code - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.2>", (bulk_query::Code, String)},
    {152, BulkLeaseQueryBaseTime, "BLQ base time - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.3>", (u32)},
    {153, BulkLeasQueryStartTimeOfState, "BLQ start time of state - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.4>", (u32)},
    {154, BulkLeaseQueryQueryStartTime, "BLQ query start time - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.5>", (u32)},
    {155, BulkLeaseQueryQueryEndTime, "BLQ query end time- <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.6>", (u32)},
    {156, BulkLeaseQueryDhcpState, "BLQ DHCP state - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.7>", (bulk_query::QueryState)},
    {157, BulkLeaseQueryDataSource, "BLQ data source - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.8>", (bulk_query::DataSourceFlags)},
    {255, End, "end-of-list marker"}
);
/// ex
/// ```rust
/// use dhcproto::v4;
///
/// let mut msg = v4::Message::default();
///  msg.opts_mut()
///     .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
///  msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(
///      vec![0, 1, 2, 3, 4, 5],
///  ));
///  msg.opts_mut()
///      .insert(v4::DhcpOption::ParameterRequestList(vec![
///          v4::OptionCode::SubnetMask,
///          v4::OptionCode::Router,
///          v4::OptionCode::DomainNameServer,
///          v4::OptionCode::DomainName,
///       ]));
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DhcpOptions(HashMap<OptionCode, DhcpOption>);

impl DhcpOptions {
    /// Create new [`DhcpOptions`]
    ///
    /// [`DhcpOptions`]: crate::v4::DhcpOptions
    pub fn new() -> Self {
        Self::default()
    }
    /// Get the data for a particular [`OptionCode`]
    ///
    /// [`OptionCode`]: crate::v4::OptionCode
    pub fn get(&self, code: OptionCode) -> Option<&DhcpOption> {
        self.0.get(&code)
    }
    /// Get the mutable data for a particular [`OptionCode`]
    ///
    /// [`OptionCode`]: crate::v4::OptionCode
    pub fn get_mut(&mut self, code: OptionCode) -> Option<&mut DhcpOption> {
        self.0.get_mut(&code)
    }
    /// remove option
    pub fn remove(&mut self, code: OptionCode) -> Option<DhcpOption> {
        self.0.remove(&code)
    }
    /// insert a new [`DhcpOption`]
    ///
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Discover));
    /// ```
    /// [`DhcpOption`]: crate::v4::DhcpOption
    pub fn insert(&mut self, opt: DhcpOption) -> Option<DhcpOption> {
        self.0.insert((&opt).into(), opt)
    }
    /// iterate over entries
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Offer));
    /// opts.insert(DhcpOption::SubnetMask([198, 168, 0, 1].into()));
    /// for (code, opt) in opts.iter() {
    ///     println!("{code:?} {opt:?}");
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&OptionCode, &DhcpOption)> {
        self.0.iter()
    }
    /// iterate mutably over entries
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&OptionCode, &mut DhcpOption)> {
        self.0.iter_mut()
    }
    /// return message type
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Offer));
    /// assert_eq!(opts.msg_type(), Some(MessageType::Offer));
    /// ```
    pub fn msg_type(&self) -> Option<MessageType> {
        let opt = self.get(OptionCode::MessageType)?;
        match opt {
            DhcpOption::MessageType(mtype) => Some(*mtype),
            _ => unreachable!("cannot return different option for MessageType"),
        }
    }
    /// determine if options contains a specific message type
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Offer));
    /// assert!(opts.has_msg_type(MessageType::Offer));
    /// assert!(!opts.has_msg_type(MessageType::Decline));
    /// ```
    pub fn has_msg_type(&self, opt: MessageType) -> bool {
        matches!(self.get(OptionCode::MessageType), Some(DhcpOption::MessageType(msg)) if *msg == opt)
    }
    /// clear all options
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Discover));
    /// assert!(opts.len() == 1);
    /// opts.clear(); // clear options
    /// assert!(opts.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.0.clear()
    }
    /// Returns `true` if there are no options
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Offer));
    /// assert!(!opts.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Retains only the elements specified by the predicate
    pub fn retain<F>(&mut self, pred: F)
    where
        F: FnMut(&OptionCode, &mut DhcpOption) -> bool,
    {
        self.0.retain(pred)
    }
    /// Returns number of Options
    /// ```
    /// # use dhcproto::v4::{MessageType, DhcpOption, DhcpOptions};
    /// let mut opts = DhcpOptions::new();
    /// opts.insert(DhcpOption::MessageType(MessageType::Offer));
    /// assert_eq!(opts.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl IntoIterator for DhcpOptions {
    type Item = (OptionCode, DhcpOption);
    type IntoIter = std::collections::hash_map::IntoIter<OptionCode, DhcpOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<DhcpOption> for DhcpOptions {
    fn from_iter<T: IntoIterator<Item = DhcpOption>>(iter: T) -> Self {
        DhcpOptions(
            iter.into_iter()
                .map(|opt| ((&opt).into(), opt))
                .collect::<HashMap<OptionCode, DhcpOption>>(),
        )
    }
}

impl FromIterator<(OptionCode, DhcpOption)> for DhcpOptions {
    fn from_iter<T: IntoIterator<Item = (OptionCode, DhcpOption)>>(iter: T) -> Self {
        DhcpOptions(iter.into_iter().collect::<HashMap<_, _>>())
    }
}

impl Decodable for DhcpOptions {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        // represented as a vector in the actual message
        let mut opts = HashMap::new();
        // should we error the whole parser if we fail to parse an
        // option or just stop parsing options? -- here we will just stop
        while let Ok(opt) = DhcpOption::decode(decoder) {
            // we throw away PAD bytes here
            match opt {
                DhcpOption::End => {
                    break;
                }
                DhcpOption::Pad => {}
                _ => {
                    opts.insert(OptionCode::from(&opt), opt);
                }
            }
        }
        Ok(DhcpOptions(opts))
    }
}

impl Encodable for DhcpOptions {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            // encode all opts adding the `End` afterwards
            // sum all bytes written
            match self.get(OptionCode::RelayAgentInformation) {
                // agent info must be placed last before `End`
                Some(agent_info) => self
                    .0
                    .iter()
                    .filter(|opt| *opt.0 != OptionCode::RelayAgentInformation)
                    .chain(iter::once((&OptionCode::RelayAgentInformation, agent_info)))
                    .chain(iter::once((&OptionCode::End, &DhcpOption::End)))
                    .try_for_each(|(_, opt)| opt.encode(e)),
                None => self
                    .0
                    .iter()
                    .chain(iter::once((&OptionCode::End, &DhcpOption::End)))
                    .try_for_each(|(_, opt)| opt.encode(e)),
            }
        }
    }
}

impl PartialOrd for OptionCode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OptionCode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u8::from(*self).cmp(&u8::from(*other))
    }
}

impl PartialOrd for DhcpOption {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DhcpOption {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        OptionCode::from(self).cmp(&OptionCode::from(other))
    }
}

/// Architecture name from - <https://www.rfc-editor.org/rfc/rfc4578.html>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// Intel x86PC
    Intelx86PC,
    /// NEC/PC98
    NECPC98,
    /// EFI Itanium
    Itanium,
    /// DEC Alpha
    DECAlpha,
    /// Arc x86
    Arcx86,
    /// Intel Lean Client
    IntelLeanClient,
    /// EFI IA32
    IA32,
    /// EFI BC
    BC,
    /// EFI Xscale
    Xscale,
    /// EFI x86-64
    X86_64,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for Architecture {
    fn from(n: u16) -> Self {
        use Architecture::*;
        match n {
            0 => Intelx86PC,
            1 => NECPC98,
            2 => Itanium,
            3 => DECAlpha,
            4 => Arcx86,
            5 => IntelLeanClient,
            6 => IA32,
            7 => BC,
            8 => Xscale,
            9 => X86_64,
            _ => Unknown(n),
        }
    }
}

impl From<Architecture> for u16 {
    fn from(n: Architecture) -> Self {
        use Architecture as A;
        match n {
            A::Intelx86PC => 0,
            A::NECPC98 => 1,
            A::Itanium => 2,
            A::DECAlpha => 3,
            A::Arcx86 => 4,
            A::IntelLeanClient => 5,
            A::IA32 => 6,
            A::BC => 7,
            A::Xscale => 8,
            A::X86_64 => 9,
            A::Unknown(n) => n,
        }
    }
}

/// NetBIOS allows several different node types
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// Broadcast
    B,
    /// Peer-to-peer
    P,
    /// Mixed (B & P)
    M,
    /// Hybrid (P & B)
    H,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for NodeType {
    fn from(n: u8) -> Self {
        use NodeType::*;
        match n {
            1 => B,
            2 => P,
            4 => M,
            8 => H,
            _ => Unknown(n),
        }
    }
}

impl From<NodeType> for u8 {
    fn from(n: NodeType) -> Self {
        use NodeType as N;
        match n {
            N::B => 1,
            N::P => 2,
            N::M => 4,
            N::H => 8,
            N::Unknown(n) => n,
        }
    }
}

/// AutoConfigure option values
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AutoConfig {
    /// Do not autoconfig
    DoNotAutoConfigure = 0,
    /// autoconfig
    AutoConfigure = 1,
}

impl TryFrom<u8> for AutoConfig {
    type Error = crate::error::DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AutoConfig::DoNotAutoConfigure),
            1 => Ok(AutoConfig::AutoConfigure),
            _ => Err(super::DecodeError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid number in disable SLAAC autoconfig",
            ))),
        }
    }
}

#[inline]
fn decode_inner(
    code: OptionCode,
    len: usize,
    decoder: &mut Decoder<'_>,
) -> DecodeResult<DhcpOption> {
    use DhcpOption::*;
    Ok(match code {
        OptionCode::Pad => Pad,
        OptionCode::SubnetMask => SubnetMask(decoder.read_ipv4(len)?),
        OptionCode::TimeOffset => TimeOffset(decoder.read_i32()?),
        OptionCode::Router => Router(decoder.read_ipv4s(len)?),
        OptionCode::TimeServer => TimeServer(decoder.read_ipv4s(len)?),
        OptionCode::NameServer => NameServer(decoder.read_ipv4s(len)?),
        OptionCode::DomainNameServer => DomainNameServer(decoder.read_ipv4s(len)?),
        OptionCode::LogServer => LogServer(decoder.read_ipv4s(len)?),
        OptionCode::QuoteServer => QuoteServer(decoder.read_ipv4s(len)?),
        OptionCode::LprServer => LprServer(decoder.read_ipv4s(len)?),
        OptionCode::ImpressServer => ImpressServer(decoder.read_ipv4s(len)?),
        OptionCode::ResourceLocationServer => ResourceLocationServer(decoder.read_ipv4s(len)?),
        OptionCode::Hostname => Hostname(decoder.read_string(len)?),
        OptionCode::BootFileSize => BootFileSize(decoder.read_u16()?),
        OptionCode::MeritDumpFile => MeritDumpFile(decoder.read_string(len)?),
        OptionCode::DomainName => DomainName(decoder.read_string(len)?),
        OptionCode::SwapServer => SwapServer(decoder.read_ipv4(len)?),
        OptionCode::RootPath => RootPath(decoder.read_string(len)?),
        OptionCode::ExtensionsPath => ExtensionsPath(decoder.read_string(len)?),
        OptionCode::IpForwarding => IpForwarding(decoder.read_bool()?),
        OptionCode::NonLocalSrcRouting => NonLocalSrcRouting(decoder.read_bool()?),
        OptionCode::PolicyFilter => PolicyFilter(decoder.read_pair_ipv4s(len)?),
        OptionCode::MaxDatagramSize => MaxDatagramSize(decoder.read_u16()?),
        OptionCode::DefaultIpTtl => DefaultIpTtl(decoder.read_u8()?),
        OptionCode::PathMtuAgingTimeout => PathMtuAgingTimeout(decoder.read_u32()?),
        OptionCode::PathMtuPlateauTable => PathMtuPlateauTable({
            decoder
                .read_slice(len)?
                .chunks_exact(2)
                .map(|num| u16::from_be_bytes([num[0], num[1]]))
                .collect()
        }),
        OptionCode::InterfaceMtu => InterfaceMtu(decoder.read_u16()?),
        OptionCode::AllSubnetsLocal => AllSubnetsLocal(decoder.read_bool()?),
        OptionCode::BroadcastAddr => BroadcastAddr(decoder.read_ipv4(len)?),
        OptionCode::PerformMaskDiscovery => PerformMaskDiscovery(decoder.read_bool()?),
        OptionCode::MaskSupplier => MaskSupplier(decoder.read_bool()?),
        OptionCode::PerformRouterDiscovery => PerformRouterDiscovery(decoder.read_bool()?),
        OptionCode::RouterSolicitationAddr => RouterSolicitationAddr(decoder.read_ipv4(len)?),
        OptionCode::StaticRoutingTable => StaticRoutingTable(decoder.read_pair_ipv4s(len)?),
        OptionCode::TrailerEncapsulated => TrailerEncapsulated(decoder.read_bool()?),
        OptionCode::ArpCacheTimeout => ArpCacheTimeout(decoder.read_u32()?),
        OptionCode::EthernetEncapsulation => EthernetEncapsulation(decoder.read_bool()?),
        OptionCode::DefaultTcpTtl => DefaultIpTtl(decoder.read_u8()?),
        OptionCode::TcpKeepaliveInterval => TcpKeepaliveInterval(decoder.read_u32()?),
        OptionCode::TcpKeepaliveGarbage => TcpKeepaliveGarbage(decoder.read_bool()?),
        OptionCode::NisDomain => NisDomain(decoder.read_string(len)?),
        OptionCode::NisServers => NisServers(decoder.read_ipv4s(len)?),
        OptionCode::NtpServers => NtpServers(decoder.read_ipv4s(len)?),
        OptionCode::VendorExtensions => VendorExtensions(decoder.read_slice(len)?.to_vec()),
        OptionCode::NetBiosNameServers => NetBiosNameServers(decoder.read_ipv4s(len)?),
        OptionCode::NetBiosDatagramDistributionServer => {
            NetBiosDatagramDistributionServer(decoder.read_ipv4s(len)?)
        }
        OptionCode::NetBiosNodeType => NetBiosNodeType(decoder.read_u8()?.into()),
        OptionCode::NetBiosScope => NetBiosScope(decoder.read_string(len)?),
        OptionCode::XFontServer => XFontServer(decoder.read_ipv4s(len)?),
        OptionCode::XDisplayManager => XDisplayManager(decoder.read_ipv4s(len)?),
        OptionCode::RequestedIpAddress => RequestedIpAddress(decoder.read_ipv4(len)?),
        OptionCode::AddressLeaseTime => AddressLeaseTime(decoder.read_u32()?),
        OptionCode::OptionOverload => OptionOverload(decoder.read_u8()?),
        OptionCode::MessageType => MessageType(decoder.read_u8()?.into()),
        OptionCode::ServerIdentifier => ServerIdentifier(decoder.read_ipv4(len)?),
        OptionCode::ParameterRequestList => ParameterRequestList(
            decoder
                .read_slice(len)?
                .iter()
                .map(|code| (*code).into())
                .collect(),
        ),
        OptionCode::Message => Message(decoder.read_string(len)?),
        OptionCode::MaxMessageSize => MaxMessageSize(decoder.read_u16()?),
        OptionCode::Renewal => Renewal(decoder.read_u32()?),
        OptionCode::Rebinding => Rebinding(decoder.read_u32()?),
        OptionCode::ClassIdentifier => ClassIdentifier(decoder.read_slice(len)?.to_vec()),
        OptionCode::ClientIdentifier => ClientIdentifier(decoder.read_slice(len)?.to_vec()),
        OptionCode::NwipDomainName => NwipDomainName(decoder.read_string(len)?),
        OptionCode::NwipInformation => NwipInformation(decoder.read_slice(len)?.to_vec()),
        OptionCode::NispServiceDomain => NispServiceDomain(decoder.read_string(len)?),
        OptionCode::NispServers => NispServers(decoder.read_ipv4s(len)?),
        OptionCode::TFTPServerName => TFTPServerName(decoder.read_slice(len)?.to_vec()),
        OptionCode::BootfileName => BootfileName(decoder.read_slice(len)?.to_vec()),
        OptionCode::MobileIpHomeAgent => MobileIpHomeAgent(decoder.read_ipv4s(len)?),
        OptionCode::SmtpServer => SmtpServer(decoder.read_ipv4s(len)?),
        OptionCode::Pop3Server => Pop3Server(decoder.read_ipv4s(len)?),
        OptionCode::NntpServer => NntpServer(decoder.read_ipv4s(len)?),
        OptionCode::WwwServer => WwwServer(decoder.read_ipv4s(len)?),
        OptionCode::DefaultFingerServer => DefaultFingerServer(decoder.read_ipv4s(len)?),
        OptionCode::IrcServer => IrcServer(decoder.read_ipv4s(len)?),
        OptionCode::StreetTalkServer => StreetTalkServer(decoder.read_ipv4s(len)?),
        OptionCode::StreetTalkDirectoryAssistance => {
            StreetTalkDirectoryAssistance(decoder.read_ipv4s(len)?)
        }
        OptionCode::UserClass => UserClass(decoder.read_slice(len)?.to_vec()),

        OptionCode::RapidCommit => {
            debug_assert!(len == 0);
            RapidCommit
        }
        OptionCode::RelayAgentInformation => {
            let mut dec = Decoder::new(decoder.read_slice(len)?);
            RelayAgentInformation(relay::RelayAgentInformation::decode(&mut dec)?)
        }
        OptionCode::BcmsControllerNames => BcmsControllerNames(decoder.read_domains(len)?),
        OptionCode::BcmsControllerAddrs => BcmsControllerAddrs(decoder.read_ipv4s(len)?),
        OptionCode::ClientLastTransactionTime => ClientLastTransactionTime(decoder.read_u32()?),
        OptionCode::AssociatedIp => AssociatedIp(decoder.read_ipv4s(len)?),
        OptionCode::ClientSystemArchitecture => {
            let ty = decoder.read_u16()?;
            ClientSystemArchitecture(ty.into())
        }
        OptionCode::ClientNetworkInterface => {
            debug_assert!(len == 3);
            ClientNetworkInterface(decoder.read_u8()?, decoder.read_u8()?, decoder.read_u8()?)
        }
        OptionCode::ClientMachineIdentifier => {
            ClientMachineIdentifier(decoder.read_slice(len)?.to_vec())
        }
        OptionCode::Ipv6OnlyPreferred => Ipv6OnlyPreferred(decoder.read_u32()?),
        OptionCode::CaptivePortal => CaptivePortal(decoder.read_str(len)?.parse()?),
        OptionCode::DisableSLAAC => DisableSLAAC(decoder.read_u8()?.try_into()?),
        OptionCode::SubnetSelection => SubnetSelection(decoder.read_ipv4(len)?),
        OptionCode::DomainSearch => DomainSearch(decoder.read_domains(len)?),
        OptionCode::TFTPServerAddress => TFTPServerAddress(decoder.read_ipv4(len)?),
        OptionCode::BulkLeaseQueryStatusCode => {
            let code = decoder.read_u8()?.into();
            // len - 1 because code is included in length
            let message = decoder.read_string(len - 1)?;
            BulkLeaseQueryStatusCode(code, message)
        }
        OptionCode::BulkLeaseQueryBaseTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryBaseTime(decoder.read_u32()?)
        }
        OptionCode::BulkLeasQueryStartTimeOfState => {
            debug_assert!(len == 4);
            BulkLeasQueryStartTimeOfState(decoder.read_u32()?)
        }
        OptionCode::BulkLeaseQueryQueryStartTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryQueryStartTime(decoder.read_u32()?)
        }
        OptionCode::BulkLeaseQueryQueryEndTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryQueryEndTime(decoder.read_u32()?)
        }
        OptionCode::BulkLeaseQueryDhcpState => BulkLeaseQueryDhcpState(decoder.read_u8()?.into()),
        OptionCode::BulkLeaseQueryDataSource => {
            BulkLeaseQueryDataSource(bulk_query::DataSourceFlags::new(decoder.read_u8()?))
        }
        OptionCode::ClientFQDN => {
            debug_assert!(len >= 3);
            let flags = decoder.read_u8()?.into();
            let rcode1 = decoder.read_u8()?;
            let rcode2 = decoder.read_u8()?;

            let mut name_decoder = BinDecoder::new(decoder.read_slice(len - 3)?);
            let name = Name::read(&mut name_decoder)?;
            ClientFQDN(fqdn::ClientFQDN {
                flags,
                r1: rcode1,
                r2: rcode2,
                domain: name,
            })
        }
        OptionCode::ClasslessStaticRoute => {
            let mut routes = Vec::new();

            let mut route_dec = Decoder::new(decoder.read_slice(len)?);
            while let Ok(prefix_len) = route_dec.read_u8() {
                if prefix_len > 32 {
                    break;
                }

                // Significant bytes to hold the prefix
                let sig_bytes = (prefix_len as usize + 7) / 8;

                let mut dest = [0u8; 4];
                dest[0..sig_bytes].clone_from_slice(route_dec.read_slice(sig_bytes)?);

                let dest = Ipv4Net::new(dest.into(), prefix_len).unwrap();
                let gw = route_dec.read_ipv4(4)?;

                routes.push((dest, gw));
            }

            ClasslessStaticRoute(routes)
        }
        OptionCode::End => End,
        // not yet implemented
        OptionCode::Unknown(code) => {
            let data = decoder.read_slice(len)?.to_vec();
            Unknown(UnknownOption { code, data })
        }
    })
}

impl Decodable for DhcpOption {
    #[inline]
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        #[derive(Debug)]
        struct Opt<'a> {
            code: u8,
            // will contain code + len + value
            buf: Cow<'a, [u8]>,
        }

        impl<'a> Opt<'a> {
            #[inline]
            fn as_option(&self) -> DecodeResult<DhcpOption> {
                let mut opt_decoder = Decoder::new(&self.buf);
                let code = opt_decoder.read_u8()?.into();
                let _len = opt_decoder.read_u8()?; // throw out potentially invalid len

                decode_inner(code, opt_decoder.buffer().len(), &mut opt_decoder)
            }
            // can't implement Decodable b/c of lifetime issues
            fn decode(dec: &mut Decoder<'a>) -> DecodeResult<Self> {
                // TODO: necessary to call u8::from_be_bytes?
                let [code, len] = dec.peek::<2>()?;
                let buf = Cow::from(dec.read_slice(len as usize + 2)?);
                Ok(Opt { code, buf })
            }
        }

        use DhcpOption as O;
        // read the code first, determines the variant
        // pad|end have no length, so we can't read len up here
        let mut last: Option<Opt<'_>> = None;
        while let Ok(code) = decoder.peek_u8() {
            match code.into() {
                OptionCode::End => {
                    return match last {
                        Some(prev) => prev.as_option(),
                        None => {
                            decoder.read_u8()?;
                            Ok(O::End)
                        }
                    };
                }
                OptionCode::Pad => {
                    return match last {
                        Some(prev) => prev.as_option(),
                        None => {
                            decoder.read_u8()?;
                            Ok(O::Pad)
                        }
                    };
                }
                _ => {
                    last = Some(match last {
                        None => Opt::decode(decoder)?,
                        Some(mut prev) if code == prev.code => {
                            let cur = Opt::decode(decoder)?;
                            // concatention case - <https://www.rfc-editor.org/rfc/rfc3396>
                            // store the len & value in buf
                            prev.buf.to_mut().extend(&cur.buf[2..]);
                            prev
                        }
                        Some(prev) => {
                            // got different option, decode the one we've got
                            // need to stop here so we don't consume the next option's buffer
                            return prev.as_option();
                        }
                    });
                }
            }
        }
        last.ok_or(crate::error::DecodeError::NotEnoughBytes)?
            .as_option()
    }
}

/// Splits `bytes` into chunks of up to u8::MAX (255 is the max opt length),
/// where each chunk is prepended by the length of the chunk and the code.
/// ```
/// use dhcproto::{encoder::Encoder, v4::{OptionCode, encode_long_opt_bytes}};
///
/// let mut buf = Vec::new();
/// let mut e = Encoder::new(&mut buf);
/// let msg = std::iter::repeat(b'a').take(300).collect::<Vec<_>>();
/// let res = encode_long_opt_bytes(OptionCode::Message, &msg, &mut e);
/// // [code, 255, b'a', ..., code, 45, b'a', ...]
/// let mut x = vec![OptionCode::Message.into(), 255];
/// x.extend(std::iter::repeat(b'a').take(255));
/// x.push(OptionCode::Message.into());
/// x.push(45);
/// x.extend(std::iter::repeat(b'a').take(45));
///
/// assert_eq!(buf, x);
/// ```
#[inline]
pub fn encode_long_opt_bytes(
    code: OptionCode,
    bytes: &[u8],
    e: &mut Encoder<'_>,
) -> EncodeResult<()> {
    for chunk in bytes.chunks(u8::MAX as usize) {
        e.write_u8(code.into())?;
        e.write_u8(chunk.len() as u8)?;
        e.write_slice(chunk)?;
    }
    Ok(())
}

/// Encodes a list of domain `Name`s but chunked into u8::MAX pieces,
/// where each chunk is prepended by the length of the chunk and the code.
pub fn encode_long_opt_domains(
    code: OptionCode,
    names: &[Name],
    e: &mut Encoder<'_>,
) -> EncodeResult<()> {
    let mut buf = Vec::new();
    let mut name_encoder = BinEncoder::new(&mut buf);
    for name in names {
        name.emit(&mut name_encoder)?;
    }
    encode_long_opt_bytes(code, &buf, e)?;
    Ok(())
}
/// Splits `bytes` into chunks of up to u8::MAX / `factor` (255 is the max opt length),
/// where each chunk is prepended by the length of the chunk and the code.
///
/// `factor` here accounts for writing data where `T` is more than 1 byte.
///
/// INVARIANT: `factor` must equal the number of bytes in each `T`
/// ```
/// # use std::{iter, net::Ipv4Addr};
/// use dhcproto::{encoder::Encoder, v4::{OptionCode, encode_long_opt_chunks}};
///
/// let mut buf = Vec::new();
/// let mut e = Encoder::new(&mut buf);
/// let opt = iter::repeat(Ipv4Addr::from([1,2,3,4])).take(80).collect::<Vec<_>>();
/// let res = encode_long_opt_chunks(OptionCode::NisServers, 4, &opt, |ip, e| e.write_u32((*ip).into()), &mut e);
/// // [code, 252, 1,2,3,4,1,2,3,4 ..., code, 68, 1,2,3,4, ...]
/// let mut x = vec![OptionCode::NisServers.into(), 252];
/// x.extend(iter::repeat(Ipv4Addr::from([1,2,3,4])).map(|ip| u32::from(ip).to_be_bytes()).flatten().take(252));
/// x.push(OptionCode::NisServers.into());
/// x.push(68);
/// x.extend(iter::repeat(Ipv4Addr::from([1,2,3,4])).map(|ip| u32::from(ip).to_be_bytes()).flatten().take(68));
///
/// assert_eq!(buf, x);
/// ```
#[inline]
pub fn encode_long_opt_chunks<'a, T, F>(
    code: OptionCode,
    factor: usize,
    data: &[T],
    f: F,
    e: &mut Encoder<'a>,
) -> EncodeResult<()>
where
    F: Fn(&T, &mut Encoder<'a>) -> EncodeResult<()>,
{
    // TODO: consider using `mem::size_of::<T>()` so we don't need factor
    // although, we would need to make OptionCode repr(u8)
    for chunk in data.chunks(u8::MAX as usize / factor) {
        e.write_u8(code.into())?;
        e.write_u8((chunk.len() * factor) as u8)?;
        for thing in chunk {
            f(thing, e)?;
        }
    }
    Ok(())
}

impl Encodable for DhcpOption {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        use DhcpOption as O;

        let code: OptionCode = self.into();
        // pad has no length, so we can't read len up here.
        // don't want to have a fall-through case either
        // so we get exhaustiveness checking, so we'll parse
        // code in each match arm
        match self {
            O::Pad | O::End => {
                e.write_u8(code.into())?;
            }
            O::RapidCommit => {
                e.write_u8(code.into())?;
                e.write_u8(0)?;
            }
            O::SubnetMask(addr)
            | O::SwapServer(addr)
            | O::BroadcastAddr(addr)
            | O::RouterSolicitationAddr(addr)
            | O::RequestedIpAddress(addr)
            | O::ServerIdentifier(addr)
            | O::SubnetSelection(addr)
            | O::TFTPServerAddress(addr) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_u32((*addr).into())?
            }
            O::TimeOffset(offset) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_i32(*offset)?
            }
            O::TimeServer(ips)
            | O::NameServer(ips)
            | O::Router(ips)
            | O::DomainNameServer(ips)
            | O::LogServer(ips)
            | O::QuoteServer(ips)
            | O::LprServer(ips)
            | O::ImpressServer(ips)
            | O::ResourceLocationServer(ips)
            | O::XFontServer(ips)
            | O::XDisplayManager(ips)
            | O::NisServers(ips)
            | O::NtpServers(ips)
            | O::NetBiosNameServers(ips)
            | O::NetBiosDatagramDistributionServer(ips)
            | O::AssociatedIp(ips)
            | O::NispServers(ips)
            | O::MobileIpHomeAgent(ips)
            | O::Pop3Server(ips)
            | O::NntpServer(ips)
            | O::WwwServer(ips)
            | O::DefaultFingerServer(ips)
            | O::StreetTalkServer(ips)
            | O::StreetTalkDirectoryAssistance(ips)
            | O::SmtpServer(ips)
            | O::IrcServer(ips)
            | O::BcmsControllerAddrs(ips) => {
                encode_long_opt_chunks(code, 4, ips, |ip, e| e.write_u32((*ip).into()), e)?;
            }
            O::Hostname(s)
            | O::MeritDumpFile(s)
            | O::DomainName(s)
            | O::ExtensionsPath(s)
            | O::NisDomain(s)
            | O::RootPath(s)
            | O::NetBiosScope(s)
            | O::Message(s)
            | O::NwipDomainName(s)
            | O::NispServiceDomain(s) => {
                encode_long_opt_bytes(code, s.as_bytes(), e)?;
            }
            O::BootFileSize(num)
            | O::MaxDatagramSize(num)
            | O::InterfaceMtu(num)
            | O::MaxMessageSize(num) => {
                e.write_u8(code.into())?;
                e.write_u8(2)?;
                e.write_u16(*num)?
            }
            O::IpForwarding(b)
            | O::NonLocalSrcRouting(b)
            | O::AllSubnetsLocal(b)
            | O::PerformMaskDiscovery(b)
            | O::MaskSupplier(b)
            | O::PerformRouterDiscovery(b)
            | O::EthernetEncapsulation(b)
            | O::TcpKeepaliveGarbage(b)
            | O::TrailerEncapsulated(b) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*b).into())?
            }
            O::DefaultIpTtl(byte) | O::DefaultTcpTtl(byte) | O::OptionOverload(byte) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8(*byte)?
            }
            O::StaticRoutingTable(pair_ips) | O::PolicyFilter(pair_ips) => {
                encode_long_opt_chunks(
                    code,
                    8,
                    pair_ips,
                    |(a, b), e| {
                        e.write_u32((*a).into())?;
                        e.write_u32((*b).into())
                    },
                    e,
                )?;
            }
            O::ArpCacheTimeout(num)
            | O::TcpKeepaliveInterval(num)
            | O::AddressLeaseTime(num)
            | O::Renewal(num)
            | O::Rebinding(num)
            | O::ClientLastTransactionTime(num)
            | O::BulkLeaseQueryBaseTime(num)
            | O::BulkLeasQueryStartTimeOfState(num)
            | O::BulkLeaseQueryQueryStartTime(num)
            | O::BulkLeaseQueryQueryEndTime(num)
            | O::PathMtuAgingTimeout(num)
            | O::Ipv6OnlyPreferred(num) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_u32(*num)?;
            }
            O::VendorExtensions(bytes)
            | O::ClassIdentifier(bytes)
            | O::ClientIdentifier(bytes)
            | O::ClientMachineIdentifier(bytes)
            | O::TFTPServerName(bytes)
            | O::BootfileName(bytes)
            | O::NwipInformation(bytes)
            | O::UserClass(bytes) => {
                encode_long_opt_bytes(code, bytes, e)?;
            }
            O::ParameterRequestList(codes) => {
                encode_long_opt_chunks(code, 1, codes, |code, e| e.write_u8((*code).into()), e)?;
            }
            O::NetBiosNodeType(ntype) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*ntype).into())?;
            }
            O::MessageType(mtype) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*mtype).into())?;
            }
            O::RelayAgentInformation(relay) => {
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                relay.encode(&mut opt_enc)?;
                // data encoded to intermediate buf
                encode_long_opt_bytes(code, &buf, e)?;
            }
            O::ClientSystemArchitecture(arch) => {
                e.write_u8(code.into())?;
                e.write_u8(2)?;
                e.write_u16((*arch).into())?;
            }
            O::ClientNetworkInterface(ty, major, minor) => {
                e.write_u8(code.into())?;
                e.write_u8(3)?;
                e.write_u8(*ty)?;
                e.write_u8(*major)?;
                e.write_u8(*minor)?;
            }
            O::CaptivePortal(url) => {
                let url = url.to_string();
                encode_long_opt_bytes(code, url.as_bytes(), e)?;
            }
            O::BulkLeaseQueryStatusCode(status_code, msg) => {
                e.write_u8(code.into())?;
                let msg = msg.as_bytes();
                e.write_u8(msg.len() as u8 + 1)?;
                e.write_u8((*status_code).into())?;
                e.write_slice(msg)?
            }
            O::BulkLeaseQueryDhcpState(state) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*state).into())?
            }
            O::BulkLeaseQueryDataSource(src) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*src).into())?
            }
            O::DomainSearch(names) | O::BcmsControllerNames(names) => {
                encode_long_opt_domains(code, names, e)?
            }
            O::ClientFQDN(fqdn) => {
                let fqdn::ClientFQDN {
                    flags,
                    r1,
                    r2,
                    domain,
                } = fqdn;
                let mut buf = vec![(*flags).into(), *r1, *r2];
                if flags.e() {
                    // emits in canonical format
                    // start encoding at byte 3 because we had some preamble
                    let mut name_encoder = BinEncoder::with_offset(&mut buf, 3, EncodeMode::Normal);
                    domain.emit_as_canonical(&mut name_encoder, true)?;
                } else {
                    // TODO: not sure if this is correct
                    buf.extend(domain.to_ascii().as_bytes());
                }
                encode_long_opt_bytes(code, &buf, e)?;
            }
            O::ClasslessStaticRoute(routes) => {
                let mut buf = Vec::new();
                let mut route_enc = Encoder::new(&mut buf);
                for (dest, gw) in routes {
                    let byte_len = (dest.prefix_len() + 7) / 8;
                    route_enc.write_u8(dest.prefix_len())?;
                    route_enc.write_slice(&dest.addr().octets()[0..byte_len as usize])?;
                    route_enc.write(gw.octets())?;
                }

                encode_long_opt_bytes(code, &buf, e)?;
            }
            O::PathMtuPlateauTable(nums) => {
                encode_long_opt_chunks(code, 2, nums, |num, e| e.write_u16(*num), e)?;
            }
            O::DisableSLAAC(val) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8(*val as u8)?;
            }
            // not yet implemented
            O::Unknown(opt) => {
                encode_long_opt_bytes(code, &opt.data, e)?;
            }
        };
        Ok(())
    }
}

/// An as-of-yet unimplemented option type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption {
    code: u8,
    data: Vec<u8>,
}

impl UnknownOption {
    pub fn new(code: OptionCode, data: Vec<u8>) -> Self {
        Self {
            code: code.into(),
            data,
        }
    }
    /// return the option code
    pub fn code(&self) -> OptionCode {
        self.code.into()
    }
    /// return the data for this option
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// consume into parts
    pub fn into_parts(self) -> (OptionCode, Vec<u8>) {
        (self.code.into(), self.data)
    }
}

impl Decodable for UnknownOption {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let code = decoder.read_u8()?;
        let length = decoder.read_u8()?;
        let bytes = decoder.read_slice(length as usize)?.to_vec();
        Ok(UnknownOption { code, data: bytes })
    }
}

impl Encodable for UnknownOption {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        // TODO: account for >255 len
        e.write_u8(self.code)?;
        e.write_u8(self.data.len() as u8)?;
        e.write_slice(&self.data)?;
        Ok(())
    }
}

/// The DHCP message type
/// <https://datatracker.ietf.org/doc/html/rfc2131#section-3.1>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// DHCPDiscover
    Discover,
    /// DHCPOffer
    Offer,
    /// DHCPRequest
    Request,
    /// DHCPDecline
    Decline,
    /// DHCPAck
    Ack,
    /// DHCPNak
    Nak,
    /// DHCPRelease
    Release,
    /// DHCPInform
    Inform,
    /// DHCPForceRenew - <https://www.rfc-editor.org/rfc/rfc3203.html>
    ForceRenew,
    /// DHCPLeaseQuery - <https://www.rfc-editor.org/rfc/rfc4388#section-6.1>
    LeaseQuery,
    /// DHCPLeaseUnassigned
    LeaseUnassigned,
    /// DHCPLeaseUnknown
    LeaseUnknown,
    /// DHCPLeaseActive
    LeaseActive,
    /// DHCPBulkLeaseQuery - <https://www.rfc-editor.org/rfc/rfc6926.html>
    BulkLeaseQuery,
    /// DHCPLeaseQueryDone
    LeaseQueryDone,
    /// DHCPActiveLeaseQuery - <https://www.rfc-editor.org/rfc/rfc7724.html>
    ActiveLeaseQuery,
    /// DHCPLeaseQueryStatus
    LeaseQueryStatus,
    /// DHCPTLS
    Tls,
    /// an unknown message type
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(n: u8) -> Self {
        match n {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            8 => MessageType::Inform,
            9 => MessageType::ForceRenew,
            10 => MessageType::LeaseQuery,
            11 => MessageType::LeaseUnassigned,
            12 => MessageType::LeaseUnknown,
            13 => MessageType::LeaseActive,
            14 => MessageType::BulkLeaseQuery,
            15 => MessageType::LeaseQueryDone,
            16 => MessageType::ActiveLeaseQuery,
            17 => MessageType::LeaseQueryStatus,
            18 => MessageType::Tls,
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
            MessageType::Ack => 5,
            MessageType::Nak => 6,
            MessageType::Release => 7,
            MessageType::Inform => 8,
            MessageType::ForceRenew => 9,
            MessageType::LeaseQuery => 10,
            MessageType::LeaseUnassigned => 11,
            MessageType::LeaseUnknown => 12,
            MessageType::LeaseActive => 13,
            MessageType::BulkLeaseQuery => 14,
            MessageType::LeaseQueryDone => 15,
            MessageType::ActiveLeaseQuery => 16,
            MessageType::LeaseQueryStatus => 17,
            MessageType::Tls => 18,
            MessageType::Unknown(n) => n,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use std::str::FromStr;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn test_opt(orig: DhcpOption, actual: Vec<u8>) -> Result<()> {
        let mut out = vec![];
        let mut enc = Encoder::new(&mut out);
        orig.encode(&mut enc)?;
        println!("encoded {:?}", enc.buffer());
        assert_eq!(out, actual);

        let decoded = DhcpOption::decode(&mut Decoder::new(&out))?;
        assert_eq!(decoded, orig);
        Ok(())
    }
    #[test]
    fn test_opts() -> Result<()> {
        let (input, len) = binput();
        println!("{input:?}");
        let opts = DhcpOptions::decode(&mut Decoder::new(&input))?;

        println!("{opts:?}");
        let mut output = Vec::new();
        opts.encode(&mut Encoder::new(&mut output))?;
        // not comparing len as we don't add PAD bytes
        // assert_eq!(input.len(), len);
        assert_eq!(opts.len(), len);
        Ok(())
    }

    #[test]
    fn test_long_opts() -> Result<()> {
        let (input, len) = long_opt();
        let opts = DhcpOptions::decode(&mut Decoder::new(&input))?;

        let mut output = Vec::new();
        opts.encode(&mut Encoder::new(&mut output))?;
        // not comparing len as we don't add PAD bytes
        // assert_eq!(input.len(), len);
        assert_eq!(opts.len(), len);
        Ok(())
    }
    #[test]
    fn test_ips() -> Result<()> {
        test_opt(
            DhcpOption::DomainNameServer(vec![
                "192.168.0.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
            ]),
            vec![6, 8, 192, 168, 0, 1, 192, 168, 1, 1],
        )?;
        Ok(())
    }

    #[test]
    fn test_ips_long() -> Result<()> {
        let ip = "192.168.0.1".parse::<Ipv4Addr>().unwrap();
        let list = std::iter::repeat(ip).take(64).collect();
        let mut bytes = std::iter::repeat(ip)
            .take(63)
            .flat_map(|ip| u32::from(ip).to_be_bytes())
            .collect::<VecDeque<u8>>();
        bytes.push_front(252);
        bytes.push_front(6);
        bytes.push_back(6);
        bytes.push_back(4);
        bytes.extend(u32::from(ip).to_be_bytes());
        test_opt(
            DhcpOption::DomainNameServer(list),
            bytes.drain(..).collect(),
        )?;
        Ok(())
    }

    #[test]
    fn test_ip() -> Result<()> {
        test_opt(
            DhcpOption::ServerIdentifier("192.168.0.1".parse::<Ipv4Addr>().unwrap()),
            vec![54, 4, 192, 168, 0, 1],
        )?;
        Ok(())
    }
    #[test]
    fn test_str() -> Result<()> {
        test_opt(
            DhcpOption::Hostname("foobar.com".to_string()),
            vec![12, 10, 102, 111, 111, 98, 97, 114, 46, 99, 111, 109],
        )?;

        Ok(())
    }
    #[test]
    fn test_byte() -> Result<()> {
        test_opt(DhcpOption::DefaultIpTtl(10), vec![23, 1, 10])?;

        Ok(())
    }
    #[test]
    fn test_num() -> Result<()> {
        test_opt(DhcpOption::Renewal(30), vec![58, 4, 0, 0, 0, 30])?;
        Ok(())
    }
    #[test]
    fn test_mtype() -> Result<()> {
        test_opt(DhcpOption::MessageType(MessageType::Offer), vec![53, 1, 2])?;

        Ok(())
    }
    #[test]
    fn test_ntype() -> Result<()> {
        test_opt(DhcpOption::NetBiosNodeType(NodeType::M), vec![46, 1, 4])?;

        Ok(())
    }

    #[test]
    fn test_pair_ips() -> Result<()> {
        test_opt(
            DhcpOption::StaticRoutingTable(vec![(
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.0.1".parse::<Ipv4Addr>().unwrap(),
            )]),
            vec![33, 8, 192, 168, 1, 1, 192, 168, 0, 1],
        )?;

        Ok(())
    }
    #[test]
    fn test_arch() -> Result<()> {
        test_opt(
            DhcpOption::ClientSystemArchitecture(Architecture::Intelx86PC),
            vec![93, 2, 0, 0],
        )?;

        Ok(())
    }

    #[test]
    fn test_captive_portal() -> Result<()> {
        let mut res = vec![114];
        let url = "https://foobar.com/".as_bytes(); // note the ending slash
        res.push(url.len() as u8);
        res.extend(url);

        test_opt(
            DhcpOption::CaptivePortal("https://foobar.com".parse()?), // url parse will add trailing slash
            res,
        )?;

        Ok(())
    }

    #[test]
    fn test_rapid_commit() -> Result<()> {
        test_opt(DhcpOption::RapidCommit, vec![80, 0])?;

        Ok(())
    }
    #[test]
    fn test_status() -> Result<()> {
        let msg = "message".to_string();
        test_opt(
            DhcpOption::BulkLeaseQueryStatusCode(bulk_query::Code::Success, msg.clone()),
            vec![
                151,
                (msg.as_bytes().len() + 1) as u8,
                0,
                b'm',
                b'e',
                b's',
                b's',
                b'a',
                b'g',
                b'e',
            ],
        )?;

        Ok(())
    }

    #[test]
    fn test_domainsearch() -> Result<()> {
        test_opt(
            DhcpOption::DomainSearch(vec![
                Name::from_str("eng.apple.com.").unwrap(),
                Name::from_str("marketing.apple.com.").unwrap(),
            ]),
            vec![
                119, 27, 3, b'e', b'n', b'g', 5, b'a', b'p', b'p', b'l', b'e', 3, b'c', b'o', b'm',
                0, 9, b'm', b'a', b'r', b'k', b'e', b't', b'i', b'n', b'g', 0xC0, 0x04,
            ],
        )?;

        Ok(())
    }

    #[test]
    fn test_client_fqdn() -> Result<()> {
        test_opt(
            DhcpOption::ClientFQDN(fqdn::ClientFQDN {
                flags: fqdn::FqdnFlags::default().set_e(true),
                r1: 0,
                r2: 0,
                domain: Name::from_str("www.google.com.").unwrap(),
            }),
            vec![
                81, 19, 0x04, 0, 0, 3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3,
                b'c', b'o', b'm', 0,
            ],
        )?;

        Ok(())
    }

    #[test]
    fn test_unknown() -> Result<()> {
        test_opt(
            DhcpOption::Unknown(UnknownOption {
                code: 240,
                data: vec![1, 2, 3, 4],
            }),
            vec![240, 4, 1, 2, 3, 4],
        )?;

        Ok(())
    }

    #[test]
    fn test_nis_server_addr() -> Result<()> {
        test_opt(
            DhcpOption::NispServers(vec![
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 2),
            ]),
            vec![65, 8, 127, 0, 0, 1, 127, 0, 0, 2],
        )?;

        Ok(())
    }

    #[test]
    fn test_classless_static_route() -> Result<()> {
        test_opt(
            DhcpOption::ClasslessStaticRoute(vec![
                ("10.0.0.0/8".parse()?, "192.168.1.1".parse()?),
                ("172.16.0.0/24".parse()?, "192.168.1.1".parse()?),
            ]),
            vec![
                121, 14, // Option & length
                8, 10, 192, 168, 1, 1, // 10.0.0.0/8 -> 192.168.1.1
                24, 172, 16, 0, 192, 168, 1, 1, // 172.16.0.0/24 -> 192.168.1.1
            ],
        )?;

        Ok(())
    }

    #[test]
    fn test_classless_static_route_long_opt() -> Result<()> {
        let buf = vec![
            121, 14, // Option & length
            8, 10, 192, 168, 1, 1, // 10.0.0.0/8 -> 192.168.1.1
            24, 172, 16, 0, 192, 168, 1, 1, // 172.16.0.0/24 -> 192.168.1.1
            121, 14, // Option & length
            8, 10, 192, 168, 1, 1, // 10.0.0.0/8 -> 192.168.1.1
            24, 172, 16, 0, 192, 168, 1, 1, // 172.16.0.0/24 -> 192.168.1.1
        ];
        let mut dec = Decoder::new(&buf);
        let opt = DhcpOption::decode(&mut dec)?;
        assert_eq!(
            DhcpOption::ClasslessStaticRoute(vec![
                ("10.0.0.0/8".parse()?, "192.168.1.1".parse()?),
                ("172.16.0.0/24".parse()?, "192.168.1.1".parse()?),
                ("10.0.0.0/8".parse()?, "192.168.1.1".parse()?),
                ("172.16.0.0/24".parse()?, "192.168.1.1".parse()?),
            ]),
            opt
        );

        Ok(())
    }

    fn binput() -> (Vec<u8>, usize) {
        (
            vec![
                53, 1, 2, 54, 4, 192, 168, 0, 1, 51, 4, 0, 0, 0, 60, 58, 4, 0, 0, 0, 30, 59, 4, 0,
                0, 0, 52, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 0, 1, 6, 8, 192, 168, 0, 1, 192,
                168, 1, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            8,
        )
    }
    fn long_opt() -> (Vec<u8>, usize) {
        // domain name server encoded in long format: 6, 4, 192, 168, 0, 1, 6, 4, 192, 168, 1, 1
        // instead of: 6, 8, 192, 168, 0, 1, 192, 168, 1, 1
        (
            vec![
                53, 1, 2, 54, 4, 192, 168, 0, 1, 51, 4, 0, 0, 0, 60, 58, 4, 0, 0, 0, 30, 59, 4, 0,
                0, 0, 52, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 0, 1, 6, 4, 192, 168, 0, 1, 6, 4,
                192, 168, 1, 1, 6, 4, 192, 1, 1, 1, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            8,
        )
    }
}
