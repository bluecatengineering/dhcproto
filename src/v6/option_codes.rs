use crate::v6::{UnknownOption, options::DhcpOption};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// option code type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OptionCode(pub u16);

#[allow(non_upper_case_globals)]
impl OptionCode {
    pub const ClientId: Self = Self(1);
    pub const ServerId: Self = Self(2);
    pub const IANA: Self = Self(3);
    pub const IATA: Self = Self(4);
    pub const IAAddr: Self = Self(5);
    pub const ORO: Self = Self(6);
    pub const Preference: Self = Self(7);
    pub const ElapsedTime: Self = Self(8);
    pub const RelayMsg: Self = Self(9);
    pub const Authentication: Self = Self(11);
    pub const ServerUnicast: Self = Self(12);
    pub const StatusCode: Self = Self(13);
    pub const RapidCommit: Self = Self(14);
    pub const UserClass: Self = Self(15);
    pub const VendorClass: Self = Self(16);
    pub const VendorOpts: Self = Self(17);
    pub const InterfaceId: Self = Self(18);
    pub const ReconfMsg: Self = Self(19);
    pub const ReconfAccept: Self = Self(20);
    pub const SipServerD: Self = Self(21);
    pub const SipServerA: Self = Self(22);
    pub const DomainNameServers: Self = Self(23);
    pub const DomainSearchList: Self = Self(24);
    pub const IAPD: Self = Self(25);
    pub const IAPrefix: Self = Self(26);
    pub const NisServers: Self = Self(27);
    pub const NispServers: Self = Self(28);
    pub const NisDomainName: Self = Self(29);
    pub const NispDomainName: Self = Self(30);
    pub const SntpServers: Self = Self(31);
    pub const InformationRefreshTime: Self = Self(32);
    pub const BcmcsServerD: Self = Self(33);
    pub const BcmcsServerA: Self = Self(34);
    pub const GeoconfCivic: Self = Self(36);
    pub const RemoteId: Self = Self(37);
    pub const SubscriberId: Self = Self(38);
    pub const ClientFqdn: Self = Self(39);
    pub const PanaAgent: Self = Self(40);
    pub const NewPosixTimezone: Self = Self(41);
    pub const NewTzdbTimezone: Self = Self(42);
    pub const ERO: Self = Self(43);
    pub const LqQuery: Self = Self(44);
    pub const ClientData: Self = Self(45);
    pub const CltTime: Self = Self(46);
    pub const LqRelayData: Self = Self(47);
    pub const LqClientLink: Self = Self(48);
    pub const Mip6Hnidf: Self = Self(49);
    pub const Mip6Vdinf: Self = Self(50);
    pub const V6Lost: Self = Self(51);
    pub const CapwapAcV6: Self = Self(52);
    pub const RelayId: Self = Self(53);
    pub const Ipv6AddressMoS: Self = Self(54);
    pub const Ipv6FQDNMoS: Self = Self(55);
    pub const NtpServer: Self = Self(56);
    pub const V6AccessDomain: Self = Self(57);
    pub const SipUaCsList: Self = Self(58);
    pub const OptBootfileUrl: Self = Self(59);
    pub const OptBootfileParam: Self = Self(60);
    pub const ClientArchType: Self = Self(61);
    pub const Nii: Self = Self(62);
    pub const Geolocation: Self = Self(63);
    pub const AftrName: Self = Self(64);
    pub const ErpLocalDomainName: Self = Self(65);
    pub const Rsoo: Self = Self(66);
    pub const PdExclude: Self = Self(67);
    pub const Vss: Self = Self(68);
    pub const Mip6Idinf: Self = Self(69);
    pub const Mip6Udinf: Self = Self(70);
    pub const Mip6Hnp: Self = Self(71);
    pub const Mip6Haa: Self = Self(72);
    pub const Mip6Haf: Self = Self(73);
    pub const RdnssSelection: Self = Self(74);
    pub const KrbPrincipalName: Self = Self(75);
    pub const KrbRealmName: Self = Self(76);
    pub const KrbDefaultRealmName: Self = Self(77);
    pub const KrbKdc: Self = Self(78);
    pub const ClientLinklayerAddr: Self = Self(79);
    pub const LinkAddress: Self = Self(80);
    pub const Radius: Self = Self(81);
    pub const SolMaxRt: Self = Self(82);
    pub const InfMaxRt: Self = Self(83);
    pub const Addrsel: Self = Self(84);
    pub const AddrselTable: Self = Self(85);
    pub const V6PcpServer: Self = Self(86);
    pub const Dhcpv4Msg: Self = Self(87);
    pub const Dhcp4ODhcp6Server: Self = Self(88);
    pub const S46Rule: Self = Self(89);
    pub const S46Br: Self = Self(90);
    pub const S46Dmr: Self = Self(91);
    pub const S46V4v6bind: Self = Self(92);
    pub const S46Portparams: Self = Self(93);
    pub const S46ContMape: Self = Self(94);
    pub const S46ContMapt: Self = Self(95);
    pub const S46ContLw: Self = Self(96);
    pub const _4Rd: Self = Self(97);
    pub const _4RdMapRule: Self = Self(98);
    pub const _4RdNonMapRule: Self = Self(99);
    pub const LqBaseTime: Self = Self(100);
    pub const LqStartTime: Self = Self(101);
    pub const LqEndTime: Self = Self(102);
    pub const DhcpCaptivePortal: Self = Self(103);
    pub const MplParameters: Self = Self(104);
    pub const AniAtt: Self = Self(105);
    pub const AniNetworkName: Self = Self(106);
    pub const AniApName: Self = Self(107);
    pub const AniApBssid: Self = Self(108);
    pub const AniOperatorId: Self = Self(109);
    pub const AniOperatorRealm: Self = Self(110);
    pub const S46Priority: Self = Self(111);
    pub const MudUrlV6: Self = Self(112);
    pub const V6Prefix64: Self = Self(113);
    pub const FBindingStatus: Self = Self(114);
    pub const FConnectFlags: Self = Self(115);
    pub const Fdnsremovalinfo: Self = Self(116);
    pub const FDNSHostName: Self = Self(117);
    pub const FDNSZoneName: Self = Self(118);
    pub const Fdnsflags: Self = Self(119);
    pub const Fexpirationtime: Self = Self(120);
    pub const FMaxUnackedBndupd: Self = Self(121);
    pub const FMclt: Self = Self(122);
    pub const FPartnerLifetime: Self = Self(123);
    pub const FPartnerLifetimeSent: Self = Self(124);
    pub const FPartnerDownTime: Self = Self(125);
    pub const FPartnerRawCltTime: Self = Self(126);
    pub const FProtocolVersion: Self = Self(127);
    pub const FKeepaliveTime: Self = Self(128);
    pub const FReconfigureData: Self = Self(129);
    pub const FRelationshipName: Self = Self(130);
    pub const FServerFlags: Self = Self(131);
    pub const FServerState: Self = Self(132);
    pub const FStartTimeOfState: Self = Self(133);
    pub const FStateExpirationTime: Self = Self(134);
    pub const RelayPort: Self = Self(135);
    pub const Ipv6AddressANDSF: Self = Self(143);
}

impl From<OptionCode> for u16 {
    fn from(opt: OptionCode) -> Self {
        opt.0
    }
}

impl From<u16> for OptionCode {
    fn from(n: u16) -> Self {
        Self(n)
    }
}

impl PartialOrd for OptionCode {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OptionCode {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl From<&DhcpOption> for OptionCode {
    fn from(opt: &DhcpOption) -> Self {
        use DhcpOption as O;
        match opt {
            O::ClientId(_) => OptionCode::ClientId,
            O::ServerId(_) => OptionCode::ServerId,
            O::IANA(_) => OptionCode::IANA,
            O::IATA(_) => OptionCode::IATA,
            O::IAAddr(_) => OptionCode::IAAddr,
            O::ORO(_) => OptionCode::ORO,
            O::Preference(_) => OptionCode::Preference,
            O::ElapsedTime(_) => OptionCode::ElapsedTime,
            O::RelayMsg(_) => OptionCode::RelayMsg,
            O::Authentication(_) => OptionCode::Authentication,
            O::ServerUnicast(_) => OptionCode::ServerUnicast,
            O::StatusCode(_) => OptionCode::StatusCode,
            O::RapidCommit => OptionCode::RapidCommit,
            O::UserClass(_) => OptionCode::UserClass,
            O::VendorClass(_) => OptionCode::VendorClass,
            O::VendorOpts(_) => OptionCode::VendorOpts,
            O::InterfaceId(_) => OptionCode::InterfaceId,
            O::ReconfMsg(_) => OptionCode::ReconfMsg,
            O::ReconfAccept => OptionCode::ReconfAccept,
            O::DomainNameServers(_) => OptionCode::DomainNameServers,
            O::DomainSearchList(_) => OptionCode::DomainSearchList,
            O::IAPD(_) => OptionCode::IAPD,
            O::IAPrefix(_) => OptionCode::IAPrefix,
            O::InformationRefreshTime(_) => OptionCode::InformationRefreshTime,
            O::NtpServer(_) => OptionCode::NtpServer,
            O::ClientArchType(_) => OptionCode::ClientArchType,
            // SolMaxRt(_) => OptionCode::SolMaxRt,
            // InfMaxRt(_) => OptionCode::InfMaxRt,
            // LqQuery(_) => OptionCode::LqQuery,
            // ClientData(_) => OptionCode::ClientData,
            // CltTime(_) => OptionCode::CltTime,
            // LqRelayData(_) => OptionCode::LqRelayData,
            // LqClientLink(_) => OptionCode::LqClientLink,
            // RelayId(_) => OptionCode::RelayId,
            // LinkAddress(_) => OptionCode::LinkAddress,
            O::Unknown(UnknownOption { code, .. }) => OptionCode(*code),
        }
    }
}
