//! Valid Option Codes for ORO
//! <https://datatracker.ietf.org/doc/html/rfc8415#section-24>

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::v6::OptionCode;
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct OROCode(pub u16);

#[allow(non_upper_case_globals)]
impl OROCode {
    /// Optional
    pub const VendorOpts: Self = Self(17);
    pub const SipServerD: Self = Self(21);
    pub const SipServerA: Self = Self(22);
    pub const DomainNameServers: Self = Self(23);
    pub const DomainSearchList: Self = Self(24);
    pub const NisServers: Self = Self(27);
    pub const NispServers: Self = Self(28);
    pub const NisDomainName: Self = Self(29);
    pub const NispDomainName: Self = Self(30);
    pub const SntpServers: Self = Self(31);
    /// Required for Information-request
    pub const InformationRefreshTime: Self = Self(32);
    pub const BcmcsServerD: Self = Self(33);
    pub const BcmcsServerA: Self = Self(34);
    pub const GeoconfCivic: Self = Self(36);
    pub const ClientFqdn: Self = Self(39);
    pub const PanaAgent: Self = Self(40);
    pub const NewPosixTimezone: Self = Self(41);
    pub const NewTzdbTimezone: Self = Self(42);
    pub const Mip6Hnidf: Self = Self(49);
    pub const Mip6Vdinf: Self = Self(50);
    pub const V6Lost: Self = Self(51);
    pub const CapwapAcV6: Self = Self(52);
    pub const Ipv6AddressMoS: Self = Self(54);
    pub const Ipv6FQDNMoS: Self = Self(55);
    pub const NtpServer: Self = Self(56);
    pub const V6AccessDomain: Self = Self(57);
    pub const SipUaCsList: Self = Self(58);
    pub const OptBootfileUrl: Self = Self(59);
    pub const OptBootfileParam: Self = Self(60);
    pub const Nii: Self = Self(62);
    pub const Geolocation: Self = Self(63);
    pub const AftrName: Self = Self(64);
    pub const ErpLocalDomainName: Self = Self(65);
    pub const PdExclude: Self = Self(67);
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
    /// Required for Solicit
    pub const SolMaxRt: Self = Self(82);
    /// Required for Information-request
    pub const InfMaxRt: Self = Self(83);
    pub const Addrsel: Self = Self(84);
    pub const AddrselTable: Self = Self(85);
    pub const V6PcpServer: Self = Self(86);
    pub const Dhcp4ODhcp6Server: Self = Self(88);
    pub const S46ContMape: Self = Self(94);
    pub const S46ContMapt: Self = Self(95);
    pub const S46ContLw: Self = Self(96);
    pub const _4Rd: Self = Self(97);
    pub const _4RdMapRule: Self = Self(98);
    pub const _4RdNonMapRule: Self = Self(99);
    pub const DhcpCaptivePortal: Self = Self(103);
    pub const MplParameters: Self = Self(104);
    pub const S46Priority: Self = Self(111);
    pub const V6Prefix64: Self = Self(113);
    pub const Ipv6AddressANDSF: Self = Self(143);
}

impl From<OROCode> for u16 {
    fn from(opt: OROCode) -> Self {
        opt.0
    }
}

// should this be a TryFrom?
impl From<u16> for OROCode {
    fn from(opt: u16) -> Self {
        OROCode(opt)
    }
}

impl From<OptionCode> for OROCode {
    fn from(opt: OptionCode) -> OROCode {
        OROCode(opt.0)
    }
}

impl From<OROCode> for OptionCode {
    fn from(opt: OROCode) -> OptionCode {
        OptionCode(opt.0)
    }
}
