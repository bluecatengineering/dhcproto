use crate::v6::options::DhcpOption;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// option code type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCode {
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAAddr,
    ORO,
    Preference,
    ElapsedTime,
    RelayMsg,
    Auth,
    Unicast,
    StatusCode,
    RapidCommit,
    UserClass,
    VendorClass,
    VendorOpts,
    InterfaceId,
    ReconfMsg,
    ReconfAccept,
    SipServerD,
    SipServerA,
    DNSServers,
    DomainList,
    IAPD,
    IAPrefix,
    NisServers,
    NispServers,
    NisDomainName,
    NispDomainName,
    SntpServers,
    InformationRefreshTime,
    BcmcsServerD,
    BcmcsServerA,
    GeoconfCivic,
    RemoteId,
    SubscriberId,
    ClientFqdn,
    PanaAgent,
    NewPosixTimezone,
    NewTzdbTimezone,
    ERO,
    LqQuery,
    ClientData,
    CltTime,
    LqRelayData,
    LqClientLink,
    Mip6Hnidf,
    Mip6Vdinf,
    V6Lost,
    CapwapAcV6,
    RelayId,
    Ipv6AddressMoS,
    Ipv6FQDNMoS,
    NtpServer,
    V6AccessDomain,
    SipUaCsList,
    OptBootfileUrl,
    OptBootfileParam,
    ClientArchType,
    Nii,
    Geolocation,
    AftrName,
    ErpLocalDomainName,
    Rsoo,
    PdExclude,
    Vss,
    Mip6Idinf,
    Mip6Udinf,
    Mip6Hnp,
    Mip6Haa,
    Mip6Haf,
    RdnssSelection,
    KrbPrincipalName,
    KrbRealmName,
    KrbDefaultRealmName,
    KrbKdc,
    ClientLinklayerAddr,
    LinkAddress,
    Radius,
    SolMaxRt,
    InfMaxRt,
    Addrsel,
    AddrselTable,
    V6PcpServer,
    Dhcpv4Msg,
    Dhcp4ODhcp6Server,
    S46Rule,
    S46Br,
    S46Dmr,
    S46V4v6bind,
    S46Portparams,
    S46ContMape,
    S46ContMapt,
    S46ContLw,
    _4Rd,
    _4RdMapRule,
    _4RdNonMapRule,
    LqBaseTime,
    LqStartTime,
    LqEndTime,
    DhcpCaptivePortal,
    MplParameters,
    AniAtt,
    AniNetworkName,
    AniApName,
    AniApBssid,
    AniOperatorId,
    AniOperatorRealm,
    S46Priority,
    MudUrlV6,
    V6Prefix64,
    FBindingStatus,
    FConnectFlags,
    Fdnsremovalinfo,
    FDNSHostName,
    FDNSZoneName,
    Fdnsflags,
    Fexpirationtime,
    FMaxUnackedBndupd,
    FMclt,
    FPartnerLifetime,
    FPartnerLifetimeSent,
    FPartnerDownTime,
    FPartnerRawCltTime,
    FProtocolVersion,
    FKeepaliveTime,
    FReconfigureData,
    FRelationshipName,
    FServerFlags,
    FServerState,
    FStartTimeOfState,
    FStateExpirationTime,
    RelayPort,
    Ipv6AddressANDSF,
    Unknown(u16),
}

impl From<OptionCode> for u16 {
    fn from(opt: OptionCode) -> Self {
        use OptionCode::*;
        match opt {
            ClientId => 1,
            ServerId => 2,
            IANA => 3,
            IATA => 4,
            IAAddr => 5,
            ORO => 6,
            Preference => 7,
            ElapsedTime => 8,
            RelayMsg => 9,
            Auth => 11,
            Unicast => 12,
            StatusCode => 13,
            RapidCommit => 14,
            UserClass => 15,
            VendorClass => 16,
            VendorOpts => 17,
            InterfaceId => 18,
            ReconfMsg => 19,
            ReconfAccept => 20,
            SipServerD => 21,
            SipServerA => 22,
            DNSServers => 23,
            DomainList => 24,
            IAPD => 25,
            IAPrefix => 26,
            NisServers => 27,
            NispServers => 28,
            NisDomainName => 29,
            NispDomainName => 30,
            SntpServers => 31,
            InformationRefreshTime => 32,
            BcmcsServerD => 33,
            BcmcsServerA => 34,
            GeoconfCivic => 36,
            RemoteId => 37,
            SubscriberId => 38,
            ClientFqdn => 39,
            PanaAgent => 40,
            NewPosixTimezone => 41,
            NewTzdbTimezone => 42,
            ERO => 43,
            LqQuery => 44,
            ClientData => 45,
            CltTime => 46,
            LqRelayData => 47,
            LqClientLink => 48,
            Mip6Hnidf => 49,
            Mip6Vdinf => 50,
            V6Lost => 51,
            CapwapAcV6 => 52,
            RelayId => 53,
            Ipv6AddressMoS => 54,
            Ipv6FQDNMoS => 55,
            NtpServer => 56,
            V6AccessDomain => 57,
            SipUaCsList => 58,
            OptBootfileUrl => 59,
            OptBootfileParam => 60,
            ClientArchType => 61,
            Nii => 62,
            Geolocation => 63,
            AftrName => 64,
            ErpLocalDomainName => 65,
            Rsoo => 66,
            PdExclude => 67,
            Vss => 68,
            Mip6Idinf => 69,
            Mip6Udinf => 70,
            Mip6Hnp => 71,
            Mip6Haa => 72,
            Mip6Haf => 73,
            RdnssSelection => 74,
            KrbPrincipalName => 75,
            KrbRealmName => 76,
            KrbDefaultRealmName => 77,
            KrbKdc => 78,
            ClientLinklayerAddr => 79,
            LinkAddress => 80,
            Radius => 81,
            SolMaxRt => 82,
            InfMaxRt => 83,
            Addrsel => 84,
            AddrselTable => 85,
            V6PcpServer => 86,
            Dhcpv4Msg => 87,
            Dhcp4ODhcp6Server => 88,
            S46Rule => 89,
            S46Br => 90,
            S46Dmr => 91,
            S46V4v6bind => 92,
            S46Portparams => 93,
            S46ContMape => 94,
            S46ContMapt => 95,
            S46ContLw => 96,
            _4Rd => 97,
            _4RdMapRule => 98,
            _4RdNonMapRule => 99,
            LqBaseTime => 100,
            LqStartTime => 101,
            LqEndTime => 102,
            DhcpCaptivePortal => 103,
            MplParameters => 104,
            AniAtt => 105,
            AniNetworkName => 106,
            AniApName => 107,
            AniApBssid => 108,
            AniOperatorId => 109,
            AniOperatorRealm => 110,
            S46Priority => 111,
            MudUrlV6 => 112,
            V6Prefix64 => 113,
            FBindingStatus => 114,
            FConnectFlags => 115,
            Fdnsremovalinfo => 116,
            FDNSHostName => 117,
            FDNSZoneName => 118,
            Fdnsflags => 119,
            Fexpirationtime => 120,
            FMaxUnackedBndupd => 121,
            FMclt => 122,
            FPartnerLifetime => 123,
            FPartnerLifetimeSent => 124,
            FPartnerDownTime => 125,
            FPartnerRawCltTime => 126,
            FProtocolVersion => 127,
            FKeepaliveTime => 128,
            FReconfigureData => 129,
            FRelationshipName => 130,
            FServerFlags => 131,
            FServerState => 132,
            FStartTimeOfState => 133,
            FStateExpirationTime => 134,
            RelayPort => 135,
            Ipv6AddressANDSF => 143,
            Unknown(n) => n,
        }
    }
}

impl From<u16> for OptionCode {
    fn from(n: u16) -> Self {
        use OptionCode::*;
        match n {
            1 => ClientId,
            2 => ServerId,
            3 => IANA,
            4 => IATA,
            5 => IAAddr,
            6 => ORO,
            7 => Preference,
            8 => ElapsedTime,
            9 => RelayMsg,
            11 => Auth,
            12 => Unicast,
            13 => StatusCode,
            14 => RapidCommit,
            15 => UserClass,
            16 => VendorClass,
            17 => VendorOpts,
            18 => InterfaceId,
            19 => ReconfMsg,
            20 => ReconfAccept,
            21 => SipServerD,
            22 => SipServerA,
            23 => DNSServers,
            24 => DomainList,
            25 => IAPD,
            26 => IAPrefix,
            27 => NisServers,
            28 => NispServers,
            29 => NisDomainName,
            30 => NispDomainName,
            31 => SntpServers,
            32 => InformationRefreshTime,
            33 => BcmcsServerD,
            34 => BcmcsServerA,
            36 => GeoconfCivic,
            37 => RemoteId,
            38 => SubscriberId,
            39 => ClientFqdn,
            40 => PanaAgent,
            41 => NewPosixTimezone,
            42 => NewTzdbTimezone,
            43 => ERO,
            44 => LqQuery,
            45 => ClientData,
            46 => CltTime,
            47 => LqRelayData,
            48 => LqClientLink,
            49 => Mip6Hnidf,
            50 => Mip6Vdinf,
            51 => V6Lost,
            52 => CapwapAcV6,
            53 => RelayId,
            54 => Ipv6AddressMoS,
            55 => Ipv6FQDNMoS,
            56 => NtpServer,
            57 => V6AccessDomain,
            58 => SipUaCsList,
            59 => OptBootfileUrl,
            60 => OptBootfileParam,
            61 => ClientArchType,
            62 => Nii,
            63 => Geolocation,
            64 => AftrName,
            65 => ErpLocalDomainName,
            66 => Rsoo,
            67 => PdExclude,
            68 => Vss,
            69 => Mip6Idinf,
            70 => Mip6Udinf,
            71 => Mip6Hnp,
            72 => Mip6Haa,
            73 => Mip6Haf,
            74 => RdnssSelection,
            75 => KrbPrincipalName,
            76 => KrbRealmName,
            77 => KrbDefaultRealmName,
            78 => KrbKdc,
            79 => ClientLinklayerAddr,
            80 => LinkAddress,
            81 => Radius,
            82 => SolMaxRt,
            83 => InfMaxRt,
            84 => Addrsel,
            85 => AddrselTable,
            86 => V6PcpServer,
            87 => Dhcpv4Msg,
            88 => Dhcp4ODhcp6Server,
            89 => S46Rule,
            90 => S46Br,
            91 => S46Dmr,
            92 => S46V4v6bind,
            93 => S46Portparams,
            94 => S46ContMape,
            95 => S46ContMapt,
            96 => S46ContLw,
            97 => _4Rd,
            98 => _4RdMapRule,
            99 => _4RdNonMapRule,
            100 => LqBaseTime,
            101 => LqStartTime,
            102 => LqEndTime,
            103 => DhcpCaptivePortal,
            104 => MplParameters,
            105 => AniAtt,
            106 => AniNetworkName,
            107 => AniApName,
            108 => AniApBssid,
            109 => AniOperatorId,
            110 => AniOperatorRealm,
            111 => S46Priority,
            112 => MudUrlV6,
            113 => V6Prefix64,
            114 => FBindingStatus,
            115 => FConnectFlags,
            116 => Fdnsremovalinfo,
            117 => FDNSHostName,
            118 => FDNSZoneName,
            119 => Fdnsflags,
            120 => Fexpirationtime,
            121 => FMaxUnackedBndupd,
            122 => FMclt,
            123 => FPartnerLifetime,
            124 => FPartnerLifetimeSent,
            125 => FPartnerDownTime,
            126 => FPartnerRawCltTime,
            127 => FProtocolVersion,
            128 => FKeepaliveTime,
            129 => FReconfigureData,
            130 => FRelationshipName,
            131 => FServerFlags,
            132 => FServerState,
            133 => FStartTimeOfState,
            134 => FStateExpirationTime,
            135 => RelayPort,
            143 => Ipv6AddressANDSF,
            _ => Unknown(n),
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
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl From<&DhcpOption> for OptionCode {
    fn from(opt: &DhcpOption) -> Self {
        use DhcpOption::*;
        match opt {
            ClientId(_) => OptionCode::ClientId,
            ServerId(_) => OptionCode::ServerId,
            IANA(_) => OptionCode::IANA,
            IATA(_) => OptionCode::IATA,
            IAAddr(_) => OptionCode::IAAddr,
            ORO(_) => OptionCode::ORO,
            Preference(_) => OptionCode::Preference,
            ElapsedTime(_) => OptionCode::ElapsedTime,
            RelayMsg(_) => OptionCode::RelayMsg,
            Auth(_) => OptionCode::Auth,
            Unicast(_) => OptionCode::Unicast,
            StatusCode(_) => OptionCode::StatusCode,
            RapidCommit(_) => OptionCode::RapidCommit,
            UserClass(_) => OptionCode::UserClass,
            VendorClass(_) => OptionCode::VendorClass,
            VendorOpts(_) => OptionCode::VendorOpts,
            InterfaceId(_) => OptionCode::InterfaceId,
            ReconfMsg(_) => OptionCode::ReconfMsg,
            ReconfAccept(_) => OptionCode::ReconfAccept,
            DNSServers(_) => OptionCode::DNSServers,
            DomainList(_) => OptionCode::DomainList,
            IAPD(_) => OptionCode::IAPD,
            IAPrefix(_) => OptionCode::IAPrefix,
            InformationRefreshTime(_) => OptionCode::InformationRefreshTime,
            SolMaxRt(_) => OptionCode::SolMaxRt,
            InfMaxRt(_) => OptionCode::InfMaxRt,
            LqQuery(_) => OptionCode::LqQuery,
            ClientData(_) => OptionCode::ClientData,
            CltTime(_) => OptionCode::CltTime,
            LqRelayData(_) => OptionCode::LqRelayData,
            LqClientLink(_) => OptionCode::LqClientLink,
            RelayId(_) => OptionCode::RelayId,
            LinkAddress(_) => OptionCode::LinkAddress,
            Unknown(unknown) => unknown.into(),
        }
    }
}
