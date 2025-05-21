//! Valid Option Codes for ORO
//! https://datatracker.ietf.org/doc/html/rfc8415#section-24

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::v6::OptionCode;
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OROCode {
    /// Optional
    VendorOpts,
    SipServerD,
    SipServerA,
    DomainNameServers,
    DomainSearchList,
    NisServers,
    NispServers,
    NisDomainName,
    NispDomainName,
    SntpServers,
    /// Required for Information-request
    InformationRefreshTime,
    BcmcsServerD,
    BcmcsServerA,
    GeoconfCivic,
    ClientFqdn,
    PanaAgent,
    NewPosixTimezone,
    NewTzdbTimezone,
    Mip6Hnidf,
    Mip6Vdinf,
    V6Lost,
    CapwapAcV6,
    Ipv6AddressMoS,
    Ipv6FQDNMoS,
    NtpServer,
    V6AccessDomain,
    SipUaCsList,
    OptBootfileUrl,
    OptBootfileParam,
    Nii,
    Geolocation,
    AftrName,
    ErpLocalDomainName,
    PdExclude,
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
    /// Required for Solicit
    SolMaxRt,
    /// Required for Information-request
    InfMaxRt,
    Addrsel,
    AddrselTable,
    V6PcpServer,
    Dhcp4ODhcp6Server,
    S46ContMape,
    S46ContMapt,
    S46ContLw,
    _4Rd,
    _4RdMapRule,
    _4RdNonMapRule,
    DhcpCaptivePortal,
    MplParameters,
    S46Priority,
    V6Prefix64,
    Ipv6AddressANDSF,
    /// Avalible for future codes.
    Unknown(u16),
}

impl From<OROCode> for u16 {
    fn from(opt: OROCode) -> Self {
        OptionCode::from(opt).into()
    }
}

// should this be a TryFrom?
impl From<u16> for OROCode {
    fn from(opt: u16) -> Self {
        OptionCode::from(opt)
            .try_into()
            .unwrap_or(OROCode::Unknown(opt))
    }
}

impl TryFrom<OptionCode> for OROCode {
    type Error = &'static str;
    fn try_from(opt: OptionCode) -> Result<OROCode, Self::Error> {
        match opt {
            OptionCode::VendorOpts => Ok(OROCode::VendorOpts),
            OptionCode::SipServerD => Ok(OROCode::SipServerD),
            OptionCode::SipServerA => Ok(OROCode::SipServerA),
            OptionCode::DomainNameServers => Ok(OROCode::DomainNameServers),
            OptionCode::DomainSearchList => Ok(OROCode::DomainSearchList),
            OptionCode::NisServers => Ok(OROCode::NisServers),
            OptionCode::NispServers => Ok(OROCode::NispServers),
            OptionCode::NisDomainName => Ok(OROCode::NisDomainName),
            OptionCode::NispDomainName => Ok(OROCode::NispDomainName),
            OptionCode::SntpServers => Ok(OROCode::SntpServers),
            OptionCode::InformationRefreshTime => Ok(OROCode::InformationRefreshTime),
            OptionCode::BcmcsServerD => Ok(OROCode::BcmcsServerD),
            OptionCode::BcmcsServerA => Ok(OROCode::BcmcsServerA),
            OptionCode::GeoconfCivic => Ok(OROCode::GeoconfCivic),
            OptionCode::ClientFqdn => Ok(OROCode::ClientFqdn),
            OptionCode::PanaAgent => Ok(OROCode::PanaAgent),
            OptionCode::NewPosixTimezone => Ok(OROCode::NewPosixTimezone),
            OptionCode::NewTzdbTimezone => Ok(OROCode::NewTzdbTimezone),
            OptionCode::Mip6Hnidf => Ok(OROCode::Mip6Hnidf),
            OptionCode::Mip6Vdinf => Ok(OROCode::Mip6Vdinf),
            OptionCode::V6Lost => Ok(OROCode::V6Lost),
            OptionCode::CapwapAcV6 => Ok(OROCode::CapwapAcV6),
            OptionCode::Ipv6AddressMoS => Ok(OROCode::Ipv6AddressMoS),
            OptionCode::Ipv6FQDNMoS => Ok(OROCode::Ipv6FQDNMoS),
            OptionCode::NtpServer => Ok(OROCode::NtpServer),
            OptionCode::V6AccessDomain => Ok(OROCode::V6AccessDomain),
            OptionCode::SipUaCsList => Ok(OROCode::SipUaCsList),
            OptionCode::OptBootfileUrl => Ok(OROCode::OptBootfileUrl),
            OptionCode::OptBootfileParam => Ok(OROCode::OptBootfileParam),
            OptionCode::Nii => Ok(OROCode::Nii),
            OptionCode::Geolocation => Ok(OROCode::Geolocation),
            OptionCode::AftrName => Ok(OROCode::AftrName),
            OptionCode::ErpLocalDomainName => Ok(OROCode::ErpLocalDomainName),
            OptionCode::PdExclude => Ok(OROCode::PdExclude),
            OptionCode::Mip6Idinf => Ok(OROCode::Mip6Idinf),
            OptionCode::Mip6Udinf => Ok(OROCode::Mip6Udinf),
            OptionCode::Mip6Hnp => Ok(OROCode::Mip6Hnp),
            OptionCode::Mip6Haa => Ok(OROCode::Mip6Haa),
            OptionCode::Mip6Haf => Ok(OROCode::Mip6Haf),
            OptionCode::RdnssSelection => Ok(OROCode::RdnssSelection),
            OptionCode::KrbPrincipalName => Ok(OROCode::KrbPrincipalName),
            OptionCode::KrbRealmName => Ok(OROCode::KrbRealmName),
            OptionCode::KrbDefaultRealmName => Ok(OROCode::KrbDefaultRealmName),
            OptionCode::KrbKdc => Ok(OROCode::KrbKdc),
            OptionCode::SolMaxRt => Ok(OROCode::SolMaxRt),
            OptionCode::InfMaxRt => Ok(OROCode::InfMaxRt),
            OptionCode::Addrsel => Ok(OROCode::Addrsel),
            OptionCode::AddrselTable => Ok(OROCode::AddrselTable),
            OptionCode::V6PcpServer => Ok(OROCode::V6PcpServer),
            OptionCode::Dhcp4ODhcp6Server => Ok(OROCode::Dhcp4ODhcp6Server),
            OptionCode::S46ContMape => Ok(OROCode::S46ContMape),
            OptionCode::S46ContMapt => Ok(OROCode::S46ContMapt),
            OptionCode::S46ContLw => Ok(OROCode::S46ContLw),
            OptionCode::_4Rd => Ok(OROCode::_4Rd),
            OptionCode::_4RdMapRule => Ok(OROCode::_4RdMapRule),
            OptionCode::_4RdNonMapRule => Ok(OROCode::_4RdNonMapRule),
            OptionCode::DhcpCaptivePortal => Ok(OROCode::DhcpCaptivePortal),
            OptionCode::MplParameters => Ok(OROCode::MplParameters),
            OptionCode::S46Priority => Ok(OROCode::S46Priority),
            OptionCode::V6Prefix64 => Ok(OROCode::V6Prefix64),
            OptionCode::Ipv6AddressANDSF => Ok(OROCode::Ipv6AddressANDSF),
            OptionCode::Unknown(u16) => Ok(OROCode::Unknown(u16)),
            _ => Err("conversion error, is not a valid OROCode"),
        }
    }
}

impl From<OROCode> for OptionCode {
    fn from(opt: OROCode) -> OptionCode {
        match opt {
            OROCode::VendorOpts => OptionCode::VendorOpts,
            OROCode::SipServerD => OptionCode::SipServerD,
            OROCode::SipServerA => OptionCode::SipServerA,
            OROCode::DomainNameServers => OptionCode::DomainNameServers,
            OROCode::DomainSearchList => OptionCode::DomainSearchList,
            OROCode::NisServers => OptionCode::NisServers,
            OROCode::NispServers => OptionCode::NispServers,
            OROCode::NisDomainName => OptionCode::NisDomainName,
            OROCode::NispDomainName => OptionCode::NispDomainName,
            OROCode::SntpServers => OptionCode::SntpServers,
            OROCode::InformationRefreshTime => OptionCode::InformationRefreshTime,
            OROCode::BcmcsServerD => OptionCode::BcmcsServerD,
            OROCode::BcmcsServerA => OptionCode::BcmcsServerA,
            OROCode::GeoconfCivic => OptionCode::GeoconfCivic,
            OROCode::ClientFqdn => OptionCode::ClientFqdn,
            OROCode::PanaAgent => OptionCode::PanaAgent,
            OROCode::NewPosixTimezone => OptionCode::NewPosixTimezone,
            OROCode::NewTzdbTimezone => OptionCode::NewTzdbTimezone,
            OROCode::Mip6Hnidf => OptionCode::Mip6Hnidf,
            OROCode::Mip6Vdinf => OptionCode::Mip6Vdinf,
            OROCode::V6Lost => OptionCode::V6Lost,
            OROCode::CapwapAcV6 => OptionCode::CapwapAcV6,
            OROCode::Ipv6AddressMoS => OptionCode::Ipv6AddressMoS,
            OROCode::Ipv6FQDNMoS => OptionCode::Ipv6FQDNMoS,
            OROCode::NtpServer => OptionCode::NtpServer,
            OROCode::V6AccessDomain => OptionCode::V6AccessDomain,
            OROCode::SipUaCsList => OptionCode::SipUaCsList,
            OROCode::OptBootfileUrl => OptionCode::OptBootfileUrl,
            OROCode::OptBootfileParam => OptionCode::OptBootfileParam,
            OROCode::Nii => OptionCode::Nii,
            OROCode::Geolocation => OptionCode::Geolocation,
            OROCode::AftrName => OptionCode::AftrName,
            OROCode::ErpLocalDomainName => OptionCode::ErpLocalDomainName,
            OROCode::PdExclude => OptionCode::PdExclude,
            OROCode::Mip6Idinf => OptionCode::Mip6Idinf,
            OROCode::Mip6Udinf => OptionCode::Mip6Udinf,
            OROCode::Mip6Hnp => OptionCode::Mip6Hnp,
            OROCode::Mip6Haa => OptionCode::Mip6Haa,
            OROCode::Mip6Haf => OptionCode::Mip6Haf,
            OROCode::RdnssSelection => OptionCode::RdnssSelection,
            OROCode::KrbPrincipalName => OptionCode::KrbPrincipalName,
            OROCode::KrbRealmName => OptionCode::KrbRealmName,
            OROCode::KrbDefaultRealmName => OptionCode::KrbDefaultRealmName,
            OROCode::KrbKdc => OptionCode::KrbKdc,
            OROCode::SolMaxRt => OptionCode::SolMaxRt,
            OROCode::InfMaxRt => OptionCode::InfMaxRt,
            OROCode::Addrsel => OptionCode::Addrsel,
            OROCode::AddrselTable => OptionCode::AddrselTable,
            OROCode::V6PcpServer => OptionCode::V6PcpServer,
            OROCode::Dhcp4ODhcp6Server => OptionCode::Dhcp4ODhcp6Server,
            OROCode::S46ContMape => OptionCode::S46ContMape,
            OROCode::S46ContMapt => OptionCode::S46ContMapt,
            OROCode::S46ContLw => OptionCode::S46ContLw,
            OROCode::_4Rd => OptionCode::_4Rd,
            OROCode::_4RdMapRule => OptionCode::_4RdMapRule,
            OROCode::_4RdNonMapRule => OptionCode::_4RdNonMapRule,
            OROCode::DhcpCaptivePortal => OptionCode::DhcpCaptivePortal,
            OROCode::MplParameters => OptionCode::MplParameters,
            OROCode::S46Priority => OptionCode::S46Priority,
            OROCode::V6Prefix64 => OptionCode::V6Prefix64,
            OROCode::Ipv6AddressANDSF => OptionCode::Ipv6AddressANDSF,
            OROCode::Unknown(u16) => OptionCode::Unknown(u16),
        }
    }
}
