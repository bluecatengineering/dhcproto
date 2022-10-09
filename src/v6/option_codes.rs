use crate::v6::DhcpOption;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// option code type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCode {
    /// 1
    ClientId, // should duid for this be bytes or string?
    /// 2
    ServerId,
    /// 3
    IANA,
    /// 4
    IATA,
    /// 5
    IAAddr,
    /// 6
    ORO,
    /// 7
    Preference,
    /// 8
    ElapsedTime,
    /// 9
    RelayMsg,
    /// 11
    Authentication,
    /// 12
    ServerUnicast,
    /// 13
    StatusCode,
    /// 14
    RapidCommit,
    /// 15
    UserClass,
    /// 16
    VendorClass,
    /// 17
    VendorOpts,
    /// 18
    InterfaceId,
    /// 19
    ReconfMsg,
    /// 20
    ReconfAccept,
    /// 23
    DNSNameServer,
    /// 24
    DomainSearchList,
    /// 25
    IAPD,
    /// 26
    IAPDPrefix,
    /// an unknown or unimplemented option type
    Unknown(u16),
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
            Authentication => 11,
            ServerUnicast => 12,
            StatusCode => 13,
            RapidCommit => 14,
            UserClass => 15,
            VendorClass => 16,
            VendorOpts => 17,
            InterfaceId => 18,
            ReconfMsg => 19,
            ReconfAccept => 20,
            DNSNameServer => 23,
            DomainSearchList => 24,
            IAPD => 25,
            IAPDPrefix => 26,
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
            11 => Authentication,
            12 => ServerUnicast,
            13 => StatusCode,
            14 => RapidCommit,
            15 => UserClass,
            16 => VendorClass,
            17 => VendorOpts,
            18 => InterfaceId,
            19 => ReconfMsg,
            20 => ReconfAccept,
            23 => DNSNameServer,
            24 => DomainSearchList,
            25 => IAPD,
            26 => IAPDPrefix,
            _ => Unknown(n),
        }
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
            Authentication(_) => OptionCode::Authentication,
            ServerUnicast(_) => OptionCode::ServerUnicast,
            StatusCode(_) => OptionCode::StatusCode,
            RapidCommit => OptionCode::RapidCommit,
            UserClass(_) => OptionCode::UserClass,
            VendorClass(_) => OptionCode::VendorClass,
            VendorOpts(_) => OptionCode::VendorOpts,
            InterfaceId(_) => OptionCode::InterfaceId,
            ReconfMsg(_) => OptionCode::ReconfMsg,
            ReconfAccept => OptionCode::ReconfAccept,
            DNSNameServer(_) => OptionCode::DNSNameServer,
            DomainSearchList(_) => OptionCode::DomainSearchList,
            IAPD(_) => OptionCode::IAPD,
            IAPDPrefix(_) => OptionCode::IAPDPrefix,
            Unknown(unknown) => unknown.into(),
        }
    }
}

