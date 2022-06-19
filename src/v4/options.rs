use std::{borrow::Cow, collections::HashMap, iter, net::Ipv4Addr};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v4::bulk_query,
    v4::relay,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use trust_dns_proto::{
    rr::Name,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

/// Options for DHCP. This implemention of options ignores PAD bytes.
///
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

impl Decodable<'_> for DhcpOptions {
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
            self.0
                .iter()
                .chain(iter::once((&OptionCode::End, &DhcpOption::End)))
                .try_for_each(|(_, opt)| opt.encode(e))
            // TODO: no padding added for now, is it necessary?
            // apparently it's "normally" added to pad out to word sizes
            // but test packet captures are often padded to 60 bytes
            // which seems like not a word size?
        }
    }
}

/// Each option type is represented by an 8-bit code
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Hash, Clone, PartialEq, Eq)]
pub enum OptionCode {
    /// 0 Padding
    Pad,
    /// 1 Subnet Mask
    SubnetMask,
    /// 2 Time Offset
    TimeOffset,
    /// 3 Router
    Router,
    /// 4 Router
    TimeServer,
    /// 5 Name Server
    NameServer,
    /// 6 Name Server
    DomainNameServer,
    /// 7 Log Server
    LogServer,
    /// 8 Quote Server
    QuoteServer,
    /// 9 LPR Server
    LprServer,
    /// 10 Impress server
    ImpressServer,
    /// 11 Resource Location Server
    ResourceLocationServer,
    /// 12 Host name
    Hostname,
    /// 13 Boot file size
    BootFileSize,
    /// 14 Merit Dump File
    MeritDumpFile,
    /// 15 Domain Name
    DomainName,
    /// 16 Swap server
    SwapServer,
    /// 17 Root Path
    RootPath,
    /// 18 Extensions path
    ExtensionsPath,
    /// 19 IP forwarding
    IpForwarding,
    /// 20 Non-local source routing
    NonLocalSrcRouting,
    /// 22 Max Datagram reassembly size
    MaxDatagramSize,
    /// 23 Ip TTL
    DefaultIpTtl,
    /// 26 Interface MTU
    InterfaceMtu,
    /// 27 All Subnets Local
    AllSubnetsLocal,
    /// 28 Broadcast address
    BroadcastAddr,
    /// 29 Perform mask discovery
    PerformMaskDiscovery,
    /// 30 Mask supplier
    MaskSupplier,
    /// 31 Perform router discovery
    PerformRouterDiscovery,
    /// 32 Router solicitation address
    RouterSolicitationAddr,
    /// 33 Static routing table
    StaticRoutingTable,
    /// 35 ARP timeout
    ArpCacheTimeout,
    /// 36 Ethernet encapsulation
    EthernetEncapsulation,
    /// 37 Default TCP TTL
    DefaultTcpTtl,
    /// 38 TCP keepalive interval
    TcpKeepaliveInterval,
    /// 39 TCP keealive garbage
    TcpKeepaliveGarbage,
    /// 40 Network information service domain
    NISDomain,
    /// 41 Network infomration servers
    NIS,
    /// 42 NTP servers
    NTPServers,
    /// 43 Vendor Extensions
    VendorExtensions,
    /// 44 NetBIOS over TCP/IP name server
    NetBiosNameServers,
    /// 45 NetBIOS over TCP/IP Datagram Distribution Server
    NetBiosDatagramDistributionServer,
    /// 46 NetBIOS over TCP/IP Node Type
    NetBiosNodeType,
    /// 47 NetBIOS over TCP/IP Scope
    NetBiosScope,
    /// 48 X Window System Font Server
    XFontServer,
    /// 49 Window System Display Manager
    XDisplayManager,
    /// 50 Requested IP Address
    RequestedIpAddress,
    /// 51 IP Address Lease Time
    AddressLeaseTime,
    /// 52 Option Overload
    OptionOverload,
    /// 53 Message Type
    MessageType,
    /// 54 Server Identifier
    ServerIdentifier,
    /// 55 Parameter Request List
    ParameterRequestList,
    /// 56 Message
    Message,
    /// 57 Maximum DHCP Message Size
    MaxMessageSize,
    /// 58 Renewal (T1) Time Value
    Renewal,
    /// 59 Rebinding (T2) Time Value
    Rebinding,
    /// 60 Class-identifier
    ClassIdentifier,
    /// 61 Client Identifier
    ClientIdentifier,
    /// 82 Relay Agent Information
    RelayAgentInformation,
    /// 91 client-last-transaction-time - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>
    ClientLastTransactionTime,
    /// 92 associated-ip - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>
    AssociatedIp,
    /// 93 Client System Architecture - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientSystemArchitecture,
    /// 94 Client Network Interface - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientNetworkInterface,
    /// 97 Client Machine Identifier - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientMachineIdentifier,
    /// 118 Subnet option - <https://datatracker.ietf.org/doc/html/rfc3011>
    SubnetSelection,
    /// 119 Domain Search - <https://www.rfc-editor.org/rfc/rfc3397.html>
    DomainSearch,
    /// 151 status-code - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.2>
    StatusCode,
    /// 152 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.3>
    BaseTime,
    /// 153 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.4>
    StartTimeOfState,
    /// 154 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.5>
    QueryStartTime,
    /// 155 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.6>
    QueryEndTime,
    /// 156 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.7>
    DhcpState,
    /// 157 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.8>
    DataSource,
    /// Unknown option
    Unknown(u8),
    /// 255 End
    End,
}

impl From<u8> for OptionCode {
    fn from(n: u8) -> Self {
        use OptionCode::*;
        match n {
            0 => Pad,
            1 => SubnetMask,
            2 => TimeOffset,
            3 => Router,
            4 => TimeServer,
            5 => NameServer,
            6 => DomainNameServer,
            7 => LogServer,
            8 => QuoteServer,
            9 => LprServer,
            10 => ImpressServer,
            11 => ResourceLocationServer,
            12 => Hostname,
            13 => BootFileSize,
            14 => MeritDumpFile,
            15 => DomainName,
            16 => SwapServer,
            17 => RootPath,
            18 => ExtensionsPath,
            19 => IpForwarding,
            20 => NonLocalSrcRouting,
            22 => MaxDatagramSize,
            23 => DefaultIpTtl,
            26 => InterfaceMtu,
            27 => AllSubnetsLocal,
            28 => BroadcastAddr,
            29 => PerformMaskDiscovery,
            30 => MaskSupplier,
            31 => PerformRouterDiscovery,
            32 => RouterSolicitationAddr,
            33 => StaticRoutingTable,
            35 => ArpCacheTimeout,
            36 => EthernetEncapsulation,
            37 => DefaultTcpTtl,
            38 => TcpKeepaliveInterval,
            39 => TcpKeepaliveGarbage,
            40 => NISDomain,
            41 => NIS,
            42 => NTPServers,
            43 => VendorExtensions,
            44 => NetBiosNameServers,
            45 => NetBiosDatagramDistributionServer,
            46 => NetBiosNodeType,
            47 => NetBiosScope,
            48 => XFontServer,
            49 => XDisplayManager,
            50 => RequestedIpAddress,
            51 => AddressLeaseTime,
            52 => OptionOverload,
            53 => MessageType,
            54 => ServerIdentifier,
            55 => ParameterRequestList,
            56 => Message,
            57 => MaxMessageSize,
            58 => Renewal,
            59 => Rebinding,
            60 => ClassIdentifier,
            61 => ClientIdentifier,
            82 => RelayAgentInformation,
            91 => ClientLastTransactionTime,
            92 => AssociatedIp,
            93 => ClientSystemArchitecture,
            94 => ClientNetworkInterface,
            97 => ClientMachineIdentifier,
            118 => SubnetSelection,
            119 => DomainSearch,
            151 => StatusCode,
            152 => BaseTime,
            153 => StartTimeOfState,
            154 => QueryStartTime,
            155 => QueryEndTime,
            156 => DhcpState,
            157 => DataSource,
            255 => End,
            // TODO: implement more
            n => Unknown(n),
        }
    }
}

impl From<OptionCode> for u8 {
    fn from(opt: OptionCode) -> Self {
        use OptionCode::*;
        match opt {
            Pad => 0,
            SubnetMask => 1,
            TimeOffset => 2,
            Router => 3,
            TimeServer => 4,
            NameServer => 5,
            DomainNameServer => 6,
            LogServer => 7,
            QuoteServer => 8,
            LprServer => 9,
            ImpressServer => 10,
            ResourceLocationServer => 11,
            Hostname => 12,
            BootFileSize => 13,
            MeritDumpFile => 14,
            DomainName => 15,
            SwapServer => 16,
            RootPath => 17,
            ExtensionsPath => 18,
            IpForwarding => 19,
            NonLocalSrcRouting => 20,
            MaxDatagramSize => 22,
            DefaultIpTtl => 23,
            InterfaceMtu => 26,
            AllSubnetsLocal => 27,
            BroadcastAddr => 28,
            PerformMaskDiscovery => 29,
            MaskSupplier => 30,
            PerformRouterDiscovery => 31,
            RouterSolicitationAddr => 32,
            StaticRoutingTable => 33,
            ArpCacheTimeout => 35,
            EthernetEncapsulation => 36,
            DefaultTcpTtl => 37,
            TcpKeepaliveInterval => 38,
            TcpKeepaliveGarbage => 39,
            NISDomain => 40,
            NIS => 41,
            NTPServers => 42,
            VendorExtensions => 43,
            NetBiosNameServers => 44,
            NetBiosDatagramDistributionServer => 45,
            NetBiosNodeType => 46,
            NetBiosScope => 47,
            XFontServer => 48,
            XDisplayManager => 49,
            RequestedIpAddress => 50,
            AddressLeaseTime => 51,
            OptionOverload => 52,
            MessageType => 53,
            ServerIdentifier => 54,
            ParameterRequestList => 55,
            Message => 56,
            MaxMessageSize => 57,
            Renewal => 58,
            Rebinding => 59,
            ClassIdentifier => 60,
            ClientIdentifier => 61,
            RelayAgentInformation => 82,
            ClientLastTransactionTime => 91,
            AssociatedIp => 92,
            ClientSystemArchitecture => 93,
            ClientNetworkInterface => 94,
            ClientMachineIdentifier => 97,
            SubnetSelection => 118,
            DomainSearch => 119,
            StatusCode => 151,
            BaseTime => 152,
            StartTimeOfState => 153,
            QueryStartTime => 154,
            QueryEndTime => 155,
            DhcpState => 156,
            DataSource => 157,
            End => 255,
            // TODO: implement more
            Unknown(n) => n,
        }
    }
}

/// DHCP Options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// 0 Padding
    Pad,
    /// 1 Subnet Mask
    SubnetMask(Ipv4Addr),
    /// 2 Time Offset
    TimeOffset(i32),
    /// 3 Router
    Router(Vec<Ipv4Addr>),
    /// 4 Router
    TimeServer(Vec<Ipv4Addr>),
    /// 5 Name Server
    NameServer(Vec<Ipv4Addr>),
    /// 6 Name Server
    DomainNameServer(Vec<Ipv4Addr>),
    /// 7 Log Server
    LogServer(Vec<Ipv4Addr>),
    /// 8 Quote Server
    QuoteServer(Vec<Ipv4Addr>),
    /// 9 LPR Server
    LprServer(Vec<Ipv4Addr>),
    /// 10 Impress server
    ImpressServer(Vec<Ipv4Addr>),
    /// 11 Resource Location Server
    ResourceLocationServer(Vec<Ipv4Addr>),
    /// 12 Host name
    Hostname(String),
    /// 13 Boot file size
    BootFileSize(u16),
    /// 14 Merit Dump File
    MeritDumpFile(String),
    /// 15 Domain Name
    DomainName(String),
    /// 16 Swap server
    SwapServer(Ipv4Addr),
    /// 17 Root Path
    RootPath(String),
    /// 18 Extensions path
    ExtensionsPath(String),
    /// 19 IP forwarding
    IpForwarding(bool),
    /// 20 Non-local source routing
    NonLocalSrcRouting(bool),
    // TODO: Policy filter is a varlen 8 bit ipv4 / 32-bit subnetmask
    // need to think of a good way to represent this Vec<(Ipv4Addr, Ipv4Addr)>?
    // can it be changed into Ipv4Net and a prefix mask field?
    // /// 21 Policy Filter
    // PolicyFilter(Vec<Ipv4Net>),
    /// 22 Max Datagram reassembly size
    MaxDatagramSize(u16),
    /// 23 Ip TTL
    DefaultIpTtl(u8),
    /// 26 Interface MTU
    InterfaceMtu(u16),
    /// 27 All Subnets Local
    AllSubnetsLocal(bool),
    /// 28 Broadcast address
    BroadcastAddr(Ipv4Addr),
    /// 29 Perform mask discovery
    PerformMaskDiscovery(bool),
    /// 30 Mask supplier
    MaskSupplier(bool),
    /// 31 Perform router discovery
    PerformRouterDiscovery(bool),
    /// 32 Router solicitation address
    RouterSolicitationAddr(Ipv4Addr),
    /// 33 Static routing table
    StaticRoutingTable(Vec<(Ipv4Addr, Ipv4Addr)>),
    /// 35 ARP timeout
    ArpCacheTimeout(u32),
    /// 36 Ethernet encapsulation
    EthernetEncapsulation(bool),
    /// 37 Default TCP TTL
    DefaultTcpTtl(u8),
    /// 38 TCP keepalive interval
    TcpKeepaliveInterval(u32),
    /// 39 TCP keealive garbage
    TcpKeepaliveGarbage(bool),
    /// 40 Network information service domain
    NISDomain(String),
    /// 41 Network infomration servers
    NIS(Vec<Ipv4Addr>),
    /// 42 NTP servers
    NTPServers(Vec<Ipv4Addr>),
    /// 43 Vendor Extensions
    VendorExtensions(Vec<u8>),
    /// 44 NetBIOS over TCP/IP name server
    NetBiosNameServers(Vec<Ipv4Addr>),
    /// 45 NetBIOS over TCP/IP Datagram Distribution Server
    NetBiosDatagramDistributionServer(Vec<Ipv4Addr>),
    /// 46 NetBIOS over TCP/IP Node Type
    NetBiosNodeType(NodeType),
    /// 47 NetBIOS over TCP/IP Scope
    NetBiosScope(String),
    /// 48 X Window System Font Server
    XFontServer(Vec<Ipv4Addr>),
    /// 48X Window System Display Manager
    XDisplayManager(Vec<Ipv4Addr>),
    /// 50 Requested IP Address
    RequestedIpAddress(Ipv4Addr),
    /// 51 IP Address Lease Time
    AddressLeaseTime(u32),
    /// 52 Option Overload
    OptionOverload(u8),
    /// 53 Message Type
    MessageType(MessageType),
    /// 54 Server Identifier
    ServerIdentifier(Ipv4Addr),
    /// 55 Parameter Request List
    ParameterRequestList(Vec<OptionCode>),
    /// 56 Message
    Message(String),
    /// 57 Maximum DHCP Message Size
    MaxMessageSize(u16),
    /// 58 Renewal (T1) Time Value
    Renewal(u32),
    /// 59 Rebinding (T2) Time Value
    Rebinding(u32),
    /// 60 Class-identifier
    ClassIdentifier(Vec<u8>),
    /// 61 Client Identifier
    ClientIdentifier(Vec<u8>),
    /// 82 Relay Agent Information - <https://datatracker.ietf.org/doc/html/rfc3046>
    RelayAgentInformation(relay::RelayAgentInformation),
    /// 91 client-last-transaction-time - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>
    ClientLastTransactionTime(u32),
    /// 92 associated-ip - <https://www.rfc-editor.org/rfc/rfc4388.html#section-6.1>
    AssociatedIp(Vec<Ipv4Addr>),
    /// 93 Client System Architecture - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientSystemArchitecture(Architecture),
    /// 94 Client Network Interface - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientNetworkInterface(u8, u8, u8),
    /// 97 Client Machine Identifier - <https://www.rfc-editor.org/rfc/rfc4578.html>
    ClientMachineIdentifier(Vec<u8>),
    /// 118 Subnet selection - <https://datatracker.ietf.org/doc/html/rfc3011>
    SubnetSelection(Ipv4Addr),
    /// 119 Domain Search - <https://www.rfc-editor.org/rfc/rfc3397.html>
    DomainSearch(Vec<Domain>),
    /// 151 status-code - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.2>
    BulkLeaseQueryStatusCode(bulk_query::Code, String),
    /// 152 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.3>
    BulkLeaseQueryBaseTime(u32),
    /// 153 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.4>
    BulkLeasQueryStartTimeOfState(u32),
    /// 154 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.5>
    BulkLeaseQueryQueryStartTime(u32),
    /// 155 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.6>
    BulkLeaseQueryQueryEndTime(u32),
    /// 156 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.7>
    BulkLeaseQueryDhcpState(bulk_query::QueryState),
    /// 157 - <https://www.rfc-editor.org/rfc/rfc6926.html#section-6.2.8>
    BulkLeaseQueryDataSource(bulk_query::DataSourceFlags),
    /// Unknown option
    Unknown(UnknownOption),
    /// 255 End
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain(Name);

impl AsRef<Name> for Domain {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

impl AsMut<Name> for Domain {
    fn as_mut(&mut self) -> &mut Name {
        &mut self.0
    }
}

impl From<Domain> for Name {
    fn from(domain: Domain) -> Self {
        domain.0
    }
}

impl From<Name> for Domain {
    fn from(name: Name) -> Self {
        Domain(name)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self.0.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name: &str = Deserialize::deserialize(deserializer)?;
        name.parse().map(Domain).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(name),
                &"unable to parse string into Name",
            )
        })
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
        use Architecture::*;
        match n {
            Intelx86PC => 0,
            NECPC98 => 1,
            Itanium => 2,
            DECAlpha => 3,
            Arcx86 => 4,
            IntelLeanClient => 5,
            IA32 => 6,
            BC => 7,
            Xscale => 8,
            X86_64 => 9,
            Unknown(n) => n,
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
        use NodeType::*;
        match n {
            B => 1,
            P => 2,
            M => 4,
            H => 8,
            Unknown(n) => n,
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
        OptionCode::MaxDatagramSize => MaxDatagramSize(decoder.read_u16()?),
        OptionCode::DefaultIpTtl => DefaultIpTtl(decoder.read_u8()?),
        OptionCode::InterfaceMtu => InterfaceMtu(decoder.read_u16()?),
        OptionCode::AllSubnetsLocal => AllSubnetsLocal(decoder.read_bool()?),
        OptionCode::BroadcastAddr => BroadcastAddr(decoder.read_ipv4(len)?),
        OptionCode::PerformMaskDiscovery => PerformMaskDiscovery(decoder.read_bool()?),
        OptionCode::MaskSupplier => MaskSupplier(decoder.read_bool()?),
        OptionCode::PerformRouterDiscovery => PerformRouterDiscovery(decoder.read_bool()?),
        OptionCode::RouterSolicitationAddr => RouterSolicitationAddr(decoder.read_ipv4(len)?),
        OptionCode::StaticRoutingTable => StaticRoutingTable(decoder.read_pair_ipv4s(len)?),
        OptionCode::ArpCacheTimeout => ArpCacheTimeout(decoder.read_u32()?),
        OptionCode::EthernetEncapsulation => EthernetEncapsulation(decoder.read_bool()?),
        OptionCode::DefaultTcpTtl => DefaultIpTtl(decoder.read_u8()?),
        OptionCode::TcpKeepaliveInterval => TcpKeepaliveInterval(decoder.read_u32()?),
        OptionCode::TcpKeepaliveGarbage => TcpKeepaliveGarbage(decoder.read_bool()?),
        OptionCode::NISDomain => NISDomain(decoder.read_string(len)?),
        OptionCode::NIS => NIS(decoder.read_ipv4s(len)?),
        OptionCode::NTPServers => NTPServers(decoder.read_ipv4s(len)?),
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
        OptionCode::RelayAgentInformation => {
            let mut dec = Decoder::new(decoder.read_slice(len)?);
            RelayAgentInformation(relay::RelayAgentInformation::decode(&mut dec)?)
        }
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
        OptionCode::SubnetSelection => SubnetSelection(decoder.read_ipv4(len)?),
        OptionCode::DomainSearch => {
            let mut name_decoder = BinDecoder::new(decoder.read_slice(len as usize)?);
            let mut names = Vec::new();
            while let Ok(name) = Name::read(&mut name_decoder) {
                names.push(Domain(name));
            }

            DomainSearch(names)
        }
        OptionCode::StatusCode => {
            let code = decoder.read_u8()?.into();
            // len - 1 because code is included in length
            let message = decoder.read_string(len - 1)?;
            BulkLeaseQueryStatusCode(code, message)
        }
        OptionCode::BaseTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryBaseTime(decoder.read_u32()?)
        }
        OptionCode::StartTimeOfState => {
            debug_assert!(len == 4);
            BulkLeasQueryStartTimeOfState(decoder.read_u32()?)
        }
        OptionCode::QueryStartTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryQueryStartTime(decoder.read_u32()?)
        }
        OptionCode::QueryEndTime => {
            debug_assert!(len == 4);
            BulkLeaseQueryQueryEndTime(decoder.read_u32()?)
        }
        OptionCode::DhcpState => BulkLeaseQueryDhcpState(decoder.read_u8()?.into()),
        OptionCode::DataSource => {
            BulkLeaseQueryDataSource(bulk_query::DataSourceFlags::new(decoder.read_u8()?))
        }
        OptionCode::End => End,
        // not yet implemented
        OptionCode::Unknown(code) => {
            let data = decoder.read_slice(len)?.to_vec();
            Unknown(UnknownOption { code, data })
        }
    })
}

impl Decodable<'_> for DhcpOption {
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
        }

        impl<'a> Decodable<'a> for Opt<'a> {
            #[inline]
            fn decode(dec: &mut Decoder<'a>) -> DecodeResult<Self> {
                // TODO: necessary to call u8::from_be_bytes?
                let [code, len] = dec.peek::<2>()?;
                let buf = Cow::from(dec.read_slice(len as usize + 2)?);
                Ok(Opt { code, buf })
            }
        }

        use DhcpOption::*;
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
                            Ok(End)
                        }
                    };
                }
                OptionCode::Pad => {
                    return match last {
                        Some(prev) => prev.as_option(),
                        None => {
                            decoder.read_u8()?;
                            Ok(Pad)
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
/// let res = encode_long_opt_chunks(OptionCode::NIS, 4, &opt, |ip, e| e.write_u32((*ip).into()), &mut e);
/// // [code, 252, 1,2,3,4,1,2,3,4 ..., code, 68, 1,2,3,4, ...]
/// let mut x = vec![OptionCode::NIS.into(), 252];
/// x.extend(iter::repeat(Ipv4Addr::from([1,2,3,4])).map(|ip| u32::from(ip).to_be_bytes()).flatten().take(252));
/// x.push(OptionCode::NIS.into());
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
        use DhcpOption::*;

        let code: OptionCode = self.into();
        // pad has no length, so we can't read len up here.
        // don't want to have a fall-through case either
        // so we get exhaustiveness checking, so we'll parse
        // code in each match arm
        match self {
            Pad | End => {
                e.write_u8(code.into())?;
            }
            SubnetMask(addr)
            | SwapServer(addr)
            | BroadcastAddr(addr)
            | RouterSolicitationAddr(addr)
            | RequestedIpAddress(addr)
            | ServerIdentifier(addr)
            | SubnetSelection(addr) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_u32((*addr).into())?
            }
            TimeOffset(offset) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_i32(*offset)?
            }
            TimeServer(ips)
            | NameServer(ips)
            | Router(ips)
            | DomainNameServer(ips)
            | LogServer(ips)
            | QuoteServer(ips)
            | LprServer(ips)
            | ImpressServer(ips)
            | ResourceLocationServer(ips)
            | XFontServer(ips)
            | XDisplayManager(ips)
            | NIS(ips)
            | NTPServers(ips)
            | NetBiosNameServers(ips)
            | NetBiosDatagramDistributionServer(ips)
            | AssociatedIp(ips) => {
                // let bytes = ips.iter().flat_map(|a| u32::from(*a).to_be_bytes()).collect::<Vec<_>>();
                encode_long_opt_chunks(code, 4, ips, |ip, e| e.write_u32((*ip).into()), e)?;
                // e.write_u8(code.into())?;
                // e.write_u8(ips.len() as u8 * 4)?;
                // for ip in ips {
                //     e.write_u32((*ip).into())?;
                // }
            }
            Hostname(s) | MeritDumpFile(s) | DomainName(s) | ExtensionsPath(s) | NISDomain(s)
            | RootPath(s) | NetBiosScope(s) | Message(s) => {
                encode_long_opt_bytes(code, s.as_bytes(), e)?;
            }
            BootFileSize(num) | MaxDatagramSize(num) | InterfaceMtu(num) | MaxMessageSize(num) => {
                e.write_u8(code.into())?;
                e.write_u8(2)?;
                e.write_u16(*num)?
            }
            IpForwarding(b)
            | NonLocalSrcRouting(b)
            | AllSubnetsLocal(b)
            | PerformMaskDiscovery(b)
            | MaskSupplier(b)
            | PerformRouterDiscovery(b)
            | EthernetEncapsulation(b)
            | TcpKeepaliveGarbage(b) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*b).into())?
            }
            DefaultIpTtl(byte) | DefaultTcpTtl(byte) | OptionOverload(byte) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8(*byte)?
            }
            StaticRoutingTable(pair_ips) => {
                //     let bytes = pair_ips.iter().flat_map(|(a, b)| u32::from(*a).to_be_bytes().into_iter().chain(u32::from(*b).to_be_bytes())).collect::<Vec<_>>();
                //     encode_chunk_bytes(code, &bytes, e)?;
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
            ArpCacheTimeout(num)
            | TcpKeepaliveInterval(num)
            | AddressLeaseTime(num)
            | Renewal(num)
            | Rebinding(num)
            | ClientLastTransactionTime(num)
            | BulkLeaseQueryBaseTime(num)
            | BulkLeasQueryStartTimeOfState(num)
            | BulkLeaseQueryQueryStartTime(num)
            | BulkLeaseQueryQueryEndTime(num) => {
                e.write_u8(code.into())?;
                e.write_u8(4)?;
                e.write_u32(*num)?;
            }
            VendorExtensions(bytes)
            | ClassIdentifier(bytes)
            | ClientIdentifier(bytes)
            | ClientMachineIdentifier(bytes) => {
                encode_long_opt_bytes(code, bytes, e)?;
            }
            ParameterRequestList(codes) => {
                encode_long_opt_chunks(code, 1, codes, |code, e| e.write_u8((*code).into()), e)?;
            }
            NetBiosNodeType(ntype) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*ntype).into())?;
            }
            MessageType(mtype) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*mtype).into())?;
            }
            RelayAgentInformation(relay) => {
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                relay.encode(&mut opt_enc)?;
                // data encoded to intermediate buf
                encode_long_opt_bytes(code, &buf, e)?;
            }
            ClientSystemArchitecture(arch) => {
                e.write_u8(code.into())?;
                e.write_u8(2)?;
                e.write_u16((*arch).into())?;
            }
            ClientNetworkInterface(ty, major, minor) => {
                e.write_u8(code.into())?;
                e.write_u8(3)?;
                e.write_u8(*ty)?;
                e.write_u8(*major)?;
                e.write_u8(*minor)?;
            }
            BulkLeaseQueryStatusCode(status_code, msg) => {
                e.write_u8(code.into())?;
                let msg = msg.as_bytes();
                e.write_u8(msg.len() as u8 + 1)?;
                e.write_u8((*status_code).into())?;
                e.write_slice(msg)?
            }
            BulkLeaseQueryDhcpState(state) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*state).into())?
            }
            BulkLeaseQueryDataSource(src) => {
                e.write_u8(code.into())?;
                e.write_u8(1)?;
                e.write_u8((*src).into())?
            }
            DomainSearch(names) => {
                e.write_u8(code.into())?;

                let mut buf = Vec::new();
                let mut name_encoder = BinEncoder::new(&mut buf);
                for name in names {
                    name.0.emit(&mut name_encoder)?;
                }
                e.write_u8(buf.len() as u8)?;
                e.write_slice(&buf)?;
            }
            // not yet implemented
            Unknown(opt) => {
                encode_long_opt_bytes(code, &opt.data, e)?;
            }
        };
        Ok(())
    }
}

impl From<&DhcpOption> for OptionCode {
    fn from(opt: &DhcpOption) -> Self {
        use DhcpOption::*;
        match opt {
            Pad => OptionCode::Pad,
            SubnetMask(_) => OptionCode::SubnetMask,
            TimeOffset(_) => OptionCode::TimeOffset,
            Router(_) => OptionCode::Router,
            TimeServer(_) => OptionCode::TimeServer,
            NameServer(_) => OptionCode::NameServer,
            DomainNameServer(_) => OptionCode::DomainNameServer,
            LogServer(_) => OptionCode::LogServer,
            QuoteServer(_) => OptionCode::QuoteServer,
            LprServer(_) => OptionCode::LprServer,
            ImpressServer(_) => OptionCode::ImpressServer,
            ResourceLocationServer(_) => OptionCode::ResourceLocationServer,
            Hostname(_) => OptionCode::Hostname,
            BootFileSize(_) => OptionCode::BootFileSize,
            MeritDumpFile(_) => OptionCode::MeritDumpFile,
            DomainName(_) => OptionCode::DomainName,
            SwapServer(_) => OptionCode::SwapServer,
            RootPath(_) => OptionCode::RootPath,
            ExtensionsPath(_) => OptionCode::ExtensionsPath,
            IpForwarding(_) => OptionCode::IpForwarding,
            NonLocalSrcRouting(_) => OptionCode::NonLocalSrcRouting,
            MaxDatagramSize(_) => OptionCode::MaxDatagramSize,
            DefaultIpTtl(_) => OptionCode::DefaultIpTtl,
            InterfaceMtu(_) => OptionCode::InterfaceMtu,
            AllSubnetsLocal(_) => OptionCode::AllSubnetsLocal,
            BroadcastAddr(_) => OptionCode::BroadcastAddr,
            PerformMaskDiscovery(_) => OptionCode::PerformMaskDiscovery,
            MaskSupplier(_) => OptionCode::MaskSupplier,
            PerformRouterDiscovery(_) => OptionCode::PerformRouterDiscovery,
            RouterSolicitationAddr(_) => OptionCode::RouterSolicitationAddr,
            StaticRoutingTable(_) => OptionCode::StaticRoutingTable,
            ArpCacheTimeout(_) => OptionCode::ArpCacheTimeout,
            EthernetEncapsulation(_) => OptionCode::EthernetEncapsulation,
            DefaultTcpTtl(_) => OptionCode::DefaultTcpTtl,
            TcpKeepaliveInterval(_) => OptionCode::TcpKeepaliveInterval,
            TcpKeepaliveGarbage(_) => OptionCode::TcpKeepaliveGarbage,
            NISDomain(_) => OptionCode::NISDomain,
            NIS(_) => OptionCode::NIS,
            NTPServers(_) => OptionCode::NTPServers,
            VendorExtensions(_) => OptionCode::VendorExtensions,
            NetBiosNameServers(_) => OptionCode::NetBiosNameServers,
            NetBiosDatagramDistributionServer(_) => OptionCode::NetBiosDatagramDistributionServer,
            NetBiosNodeType(_) => OptionCode::NetBiosNodeType,
            NetBiosScope(_) => OptionCode::NetBiosScope,
            XFontServer(_) => OptionCode::XFontServer,
            XDisplayManager(_) => OptionCode::XDisplayManager,
            RequestedIpAddress(_) => OptionCode::RequestedIpAddress,
            AddressLeaseTime(_) => OptionCode::AddressLeaseTime,
            OptionOverload(_) => OptionCode::OptionOverload,
            MessageType(_) => OptionCode::MessageType,
            ServerIdentifier(_) => OptionCode::ServerIdentifier,
            ParameterRequestList(_) => OptionCode::ParameterRequestList,
            Message(_) => OptionCode::Message,
            MaxMessageSize(_) => OptionCode::MaxMessageSize,
            Renewal(_) => OptionCode::Renewal,
            Rebinding(_) => OptionCode::Rebinding,
            ClassIdentifier(_) => OptionCode::ClassIdentifier,
            ClientIdentifier(_) => OptionCode::ClientIdentifier,
            RelayAgentInformation(_) => OptionCode::RelayAgentInformation,
            ClientLastTransactionTime(_) => OptionCode::ClientLastTransactionTime,
            AssociatedIp(_) => OptionCode::AssociatedIp,
            ClientSystemArchitecture(_) => OptionCode::ClientSystemArchitecture,
            ClientNetworkInterface(_, _, _) => OptionCode::ClientNetworkInterface,
            ClientMachineIdentifier(_) => OptionCode::ClientMachineIdentifier,
            SubnetSelection(_) => OptionCode::SubnetSelection,
            DomainSearch(_) => OptionCode::DomainSearch,
            BulkLeaseQueryStatusCode(_, _) => OptionCode::StatusCode,
            BulkLeaseQueryBaseTime(_) => OptionCode::BaseTime,
            BulkLeasQueryStartTimeOfState(_) => OptionCode::StartTimeOfState,
            BulkLeaseQueryQueryStartTime(_) => OptionCode::QueryStartTime,
            BulkLeaseQueryQueryEndTime(_) => OptionCode::QueryEndTime,
            BulkLeaseQueryDhcpState(_) => OptionCode::DhcpState,
            BulkLeaseQueryDataSource(_) => OptionCode::DataSource,
            End => OptionCode::End,
            // TODO: implement more
            Unknown(n) => OptionCode::Unknown(n.code),
        }
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

impl Decodable<'_> for UnknownOption {
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
        println!("{:?}", input);
        let opts = DhcpOptions::decode(&mut Decoder::new(&input))?;

        println!("{:?}", opts);
        let mut output = Vec::new();
        let _len = opts.encode(&mut Encoder::new(&mut output))?;
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
                Domain(Name::from_str("eng.apple.com.").unwrap()),
                Domain(Name::from_str("marketing.apple.com.").unwrap()),
            ]),
            vec![
                119, 27, 3, b'e', b'n', b'g', 5, b'a', b'p', b'p', b'l', b'e', 3, b'c', b'o', b'm',
                0, 9, b'm', b'a', b'r', b'k', b'e', b't', b'i', b'n', b'g', 0xC0, 0x04,
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
