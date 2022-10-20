#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

//rfc8415
mod iana;
pub use iana::*;
mod iaaddr;
pub use iaaddr::*;
mod status;
pub use status::*;
mod iapd;
pub use iapd::*;
mod iaprefix;
pub use iaprefix::*;
mod iata;
pub use iata::*;
mod auth;
pub use auth::*;
mod oro;
pub use oro::*;
mod clientid;
pub use clientid::*;
mod serverid;
pub use serverid::*;
mod preference;
pub use preference::*;
mod elapsedtime;
pub use elapsedtime::*;
mod relaymsg;
pub use relaymsg::*;
mod unicast;
pub use unicast::*;
mod interfaceid;
pub use interfaceid::*;
mod rapidcommit;
pub use rapidcommit::*;
mod reconfmsg;
pub use reconfmsg::*;
mod userclass;
pub use userclass::*;
mod vendorclass;
pub use vendorclass::*;
mod vendoropts;
pub use vendoropts::*;
mod maxrt;
pub use maxrt::*;
mod informationrefreshtime;
pub use informationrefreshtime::*;

//rfc3646
mod dnsservers;
pub use dnsservers::*;
mod domainlist;
pub use domainlist::*;

//rfc5007
mod query;
pub use query::*;
mod clientdata;
pub use clientdata::*;
mod lqrelaydata;
pub use lqrelaydata::*;
mod lqclientlink;
pub use lqclientlink::*;

//rfc5460
mod relayid;
pub use relayid::*;

//rfc6977
mod linkaddress;
pub use linkaddress::*;

use std::{cmp::Ordering, net::Ipv6Addr, ops::RangeInclusive};

pub use crate::Domain;
use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::{Duid, MessageType, OROCode, OptionCode},
};

//helper macro for implementing sub-options (IANAOptions, ect)
//useage: option_builder!(IANAOption, IANAOptions, IsIANAOption, DhcpOption, IAAddr, StatusCode);
//        option_builder!(name      , names      , isname      , master    , subname...        );
macro_rules! option_builder{
    ($name: ident, $names: ident, $isname: ident, $mastername: ident, $($subnames: ident),*) => {
		pub trait $isname{
			fn code() -> OptionCode;
		}
		#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
		#[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $(
				$subnames($subnames),
			)*
				///invalid or unknown
				Unknown($mastername),
        }
		$(
			impl From<$subnames> for $name {
				fn from(sc: $subnames) -> Self{
					$name :: $subnames(sc)
				}
			}
			impl<'a> TryFrom<&'a $name> for &'a $subnames {
				type Error = &'static str;
				fn try_from(name: &'a $name) -> Result<&'a $subnames, Self::Error>{
					match name{
						$name :: $subnames(opt) => Ok(opt),
						_ => Err("$subname is not a $name"),
					}
				}
			}
			impl TryFrom<$name> for $subnames {
				type Error = &'static str;
				fn try_from(name: $name) -> Result<$subnames, Self::Error>{
					match name{
						$name :: $subnames(opt) => Ok(opt),
						_ => Err("$subname is not a $name"),
					}
				}
			}
			impl $isname for $subnames {
				fn code() -> OptionCode{
					OptionCode::$subnames
				}
			}
		)*
		impl From<&$name> for $mastername{
			fn from(option: &$name) -> Self{
				match option {
					$(
						$name :: $subnames(u) => $mastername :: $subnames(u.clone()),
					)*
						$name::Unknown(other) => other.clone(),
				}
			}
		}
		impl TryFrom<&$mastername> for $name{
			type Error=&'static str;

			fn try_from(option: &$mastername) -> Result<Self, Self::Error>{
				match option{
					$(
						$mastername :: $subnames(u) => Ok($name :: $subnames(u.clone())),
					)*
						_ => Err("invalid or unknown option"),
				}
			}
		}
		impl From<&$name> for OptionCode{
			fn from(option: &$name) -> OptionCode{
				match option{
					$(
						$name :: $subnames(_) => OptionCode :: $subnames,
					)*
						$name :: Unknown(u) => OptionCode::from(u),

				}
			}
		}
		impl Encodable for $name {
			fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
				$mastername::from(self).encode(e)
			}
		}

		impl Decodable for $name {
			fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
				let option = $mastername::decode(decoder)?;
				match (&option).try_into() {
					Ok(n) => Ok(n),
					_ => Ok($name::Unknown(option)),
				}
			}
		}
		#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
		#[derive(Debug, Clone, PartialEq, Eq, Default)]
		pub struct $names(Vec<$name>);
		impl $names {
			/// construct empty $names
			pub fn new() -> Self{
				Default::default()
			}
			/// get the first element matching this type
			pub fn get<'a, T: $isname>(&'a self) -> Option<&'a T> where &'a T: TryFrom<&'a $name>{
				use crate::v6::options::first;
				use crate::v6::OptionCode;
				let first = first(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				//unwrap can not fail, it has already been checked.
				self.0.get(first).map(|opt| <&T>::try_from(opt).ok().unwrap())
			}
			/// get all elements matching this type
			pub fn get_all<T: $isname>(&self) -> Option<&[$name]>{
				use crate::v6::options::range_binsearch;
				use crate::v6::OptionCode;
				let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				Some(&self.0[range])
			}
			/// get the first element matching the type
			pub fn get_mut<'a, T: $isname>(&'a mut self) -> Option<&'a mut T> where &'a mut T: TryFrom<&'a mut $name>{
				use crate::v6::options::first;
				use crate::v6::OptionCode;
				let first = first(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				//unwrap can not fail, it has already been checked.
				self.0.get_mut(first).map(|opt| <&mut T>::try_from(opt).ok().unwrap())
			}
			/// get all elements matching this option
			pub fn get_mut_all<T: $isname>(&mut self) -> Option<&mut [$name]>{
				use crate::v6::options::range_binsearch;
				use crate::v6::OptionCode;
				let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				Some(&mut self.0[range])
			}
			/// remove the first element with a matching type
			pub fn remove<T: $isname>(&mut self) -> Option<T> where T: TryFrom<$name>{
				use crate::v6::options::first;
				use crate::v6::OptionCode;
				let first = first(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				T::try_from(self.0.remove(first)).ok()
			}
			pub fn remove_all<T: $isname>(&mut self) -> Option<impl Iterator<Item = T> + '_> where T: TryFrom<$name>{
				use crate::v6::options::range_binsearch;
				use crate::v6::OptionCode;
				let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&T::code()))?;
				Some(self.0.drain(range).map(|opt| T::try_from(opt).ok().unwrap()))
			}
			/// insert a new option into the list of opts
			pub fn insert<T: Into<$name>>(&mut self, opt: T){
				let opt = opt.into();
				let i = self.0.partition_point(|x| OptionCode::from(x) < OptionCode::from(&opt));
				self.0.insert(i, opt)
			}
			/// return a mutable ref to an iterator
			pub fn iter(&self) -> impl Iterator<Item = &$name> {
				self.0.iter()
			}
			/// return a mutable ref to an iterator
			pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut $name> {
				self.0.iter_mut()
			}
		}
		impl Encodable for $names {
			fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
				self.0.iter().try_for_each(|opt| opt.encode(e))
			}
		}
		impl Decodable for $names {
			fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
				let mut opts = Vec::new();
				while let Ok(opt) = $name::decode(decoder) {
					opts.push(opt);
				}
				Ok($names(opts))
			}
		}
		impl IntoIterator for $names {
			type Item = $name;
			type IntoIter = std::vec::IntoIter<Self::Item>;
			fn into_iter(self) -> Self::IntoIter {
				self.0.into_iter()
			}
		}
		impl FromIterator<$name> for $names{
			fn from_iter<T: IntoIterator<Item = $name>>(iter: T) -> Self {
				let opts = iter.into_iter().collect::<Vec<_>>();
				$names(opts)
			}
		}
	};
}

pub(crate) use option_builder;

// server can send multiple IA_NA options to request multiple addresses
// so we must be able to handle multiple of the same option type
// <https://datatracker.ietf.org/doc/html/rfc8415#section-6.6>
// TODO: consider HashMap<OptionCode, TinyVec<DhcpOption>>

/// <https://datatracker.ietf.org/doc/html/rfc8415#section-21>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpOptions(Vec<DhcpOption>);
// vec maintains sorted on OptionCode

impl DhcpOptions {
    /// construct empty DhcpOptions
    pub fn new() -> Self {
        Self::default()
    }
    /// get the first element matching this option code
    pub fn get(&self, code: OptionCode) -> Option<&DhcpOption> {
        let first = first(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        // get_unchecked?
        self.0.get(first)
    }
    /// get all elements matching this option code
    pub fn get_all(&self, code: OptionCode) -> Option<&[DhcpOption]> {
        let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        Some(&self.0[range])
    }
    /// get the first element matching this option code
    pub fn get_mut(&mut self, code: OptionCode) -> Option<&mut DhcpOption> {
        let first = first(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        self.0.get_mut(first)
    }
    /// get all elements matching this option code
    pub fn get_mut_all(&mut self, code: OptionCode) -> Option<&mut [DhcpOption]> {
        let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        Some(&mut self.0[range])
    }
    /// remove the first element with a matching option code
    pub fn remove(&mut self, code: OptionCode) -> Option<DhcpOption> {
        let first = first(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        Some(self.0.remove(first))
    }
    /// remove all elements with a matching option code
    pub fn remove_all(
        &mut self,
        code: OptionCode,
    ) -> Option<impl Iterator<Item = DhcpOption> + '_> {
        let range = range_binsearch(&self.0, |x| OptionCode::from(x).cmp(&code))?;
        Some(self.0.drain(range))
    }
    /// insert a new option into the list of opts
    pub fn insert(&mut self, opt: DhcpOption) {
        let i = self.0.partition_point(|x| x < &opt);
        self.0.insert(i, opt)
    }
    /// return a reference to an iterator
    pub fn iter(&self) -> impl Iterator<Item = &DhcpOption> {
        self.0.iter()
    }
    /// return a mutable ref to an iterator
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhcpOption> {
        self.0.iter_mut()
    }
}

impl IntoIterator for DhcpOptions {
    type Item = DhcpOption;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<DhcpOption> for DhcpOptions {
    fn from_iter<T: IntoIterator<Item = DhcpOption>>(iter: T) -> Self {
        let mut opts = iter.into_iter().collect::<Vec<_>>();
        opts.sort_unstable();
        DhcpOptions(opts)
    }
}

/// DHCPv6 option types
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// 1 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.2>
    ClientId(ClientId),
    /// 2 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.3>
    ServerId(ServerId),
    /// 3 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.4>
    IANA(IANA),
    /// 4 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.5>
    IATA(IATA),
    /// 5 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.6>
    IAAddr(IAAddr),
    /// 6 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.7>
    ORO(ORO),
    /// 7 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.8>
    Preference(Preference),
    /// 8 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.9>
    /// Elapsed time in millis
    ElapsedTime(ElapsedTime),
    /// 9 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.10>
    RelayMsg(RelayMsg),
    /// 11 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.11>
    Auth(Auth),
    /// 12 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.12>
    Unicast(Unicast),
    /// 13 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.13>
    StatusCode(StatusCode),
    /// 14 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.14>
    RapidCommit(RapidCommit),
    /// 15 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.15>
    UserClass(UserClass),
    /// 16 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.16>
    VendorClass(VendorClass),
    /// 17 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.17>
    VendorOpts(VendorOpts),
    /// 18 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.18>
    InterfaceId(InterfaceId),
    /// 19 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.19>
    ReconfMsg(ReconfMsg),
    /// 20 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.20>
    ReconfAccept(ReconfAccept),
    /// 23 - <https://datatracker.ietf.org/doc/html/rfc3646>
    DNSServers(DNSServers),
    /// 24 - <https://datatracker.ietf.org/doc/html/rfc3646>
    DomainList(DomainList),
    /// 25 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.21>
    IAPD(IAPD),
    /// 26 - <https://datatracker.ietf.org/doc/html/rfc3633#section-10>
    IAPrefix(IAPrefix),
    InformationRefreshTime(InformationRefreshTime),
    SolMaxRt(SolMaxRt),
    InfMaxRt(InfMaxRt),
    LqQuery(LqQuery),
    ClientData(ClientData),
    CltTime(CltTime),
    LqRelayData(LqRelayData),
    LqClientLink(LqClientLink),
    RelayId(RelayId),
    LinkAddress(LinkAddress),
    /// An unknown or unimplemented option type
    Unknown(UnknownOption),
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

/// fallback for options not yet implemented
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption {
    code: u16,
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
    /// consume option into its components
    pub fn into_parts(self) -> (OptionCode, Vec<u8>) {
        (self.code.into(), self.data)
    }
}

impl From<&UnknownOption> for OptionCode {
    fn from(opt: &UnknownOption) -> Self {
        opt.code.into()
    }
}

impl Decodable for DhcpOptions {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let mut opts = Vec::new();
        while let Ok(opt) = DhcpOption::decode(decoder) {
            opts.push(opt);
        }
        // sorts by OptionCode
        opts.sort_unstable();
        Ok(DhcpOptions(opts))
    }
}

impl Encodable for DhcpOptions {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        self.0.iter().try_for_each(|opt| opt.encode(e))
    }
}

impl Decodable for DhcpOption {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let code = decoder.peek_u16()?.into();
        let tmp = Decoder::new(&decoder.buffer()[2..]);
        let len = tmp.peek_u16()? as usize;

        Ok(match code {
            OptionCode::ClientId => DhcpOption::ClientId(ClientId::decode(decoder)?),
            OptionCode::ServerId => DhcpOption::ServerId(ServerId::decode(decoder)?),
            OptionCode::IANA => DhcpOption::IANA(IANA::decode(decoder)?),
            OptionCode::IATA => DhcpOption::IATA(IATA::decode(decoder)?),
            OptionCode::IAAddr => DhcpOption::IAAddr(IAAddr::decode(decoder)?),
            OptionCode::ORO => DhcpOption::ORO(ORO::decode(decoder)?),
            OptionCode::Preference => DhcpOption::Preference(Preference::decode(decoder)?),
            OptionCode::ElapsedTime => DhcpOption::ElapsedTime(ElapsedTime::decode(decoder)?),
            OptionCode::RelayMsg => DhcpOption::RelayMsg(RelayMsg::decode(decoder)?),
            OptionCode::Auth => DhcpOption::Auth(Auth::decode(decoder)?),
            OptionCode::Unicast => DhcpOption::Unicast(Unicast::decode(decoder)?),
            OptionCode::StatusCode => DhcpOption::StatusCode(StatusCode::decode(decoder)?),
            OptionCode::RapidCommit => DhcpOption::RapidCommit(RapidCommit::decode(decoder)?),
            OptionCode::UserClass => DhcpOption::UserClass(UserClass::decode(decoder)?),
            OptionCode::VendorClass => DhcpOption::VendorClass(VendorClass::decode(decoder)?),
            OptionCode::VendorOpts => DhcpOption::VendorOpts(VendorOpts::decode(decoder)?),
            OptionCode::InterfaceId => DhcpOption::InterfaceId(InterfaceId::decode(decoder)?),
            OptionCode::ReconfMsg => DhcpOption::ReconfMsg(ReconfMsg::decode(decoder)?),
            OptionCode::ReconfAccept => DhcpOption::ReconfAccept(ReconfAccept::decode(decoder)?),
            OptionCode::DNSServers => DhcpOption::DNSServers(DNSServers::decode(decoder)?),
            OptionCode::IAPD => DhcpOption::IAPD(IAPD::decode(decoder)?),
            OptionCode::IAPrefix => DhcpOption::IAPrefix(IAPrefix::decode(decoder)?),
            OptionCode::InfMaxRt => DhcpOption::InfMaxRt(InfMaxRt::decode(decoder)?),
            OptionCode::InformationRefreshTime => {
                DhcpOption::InformationRefreshTime(InformationRefreshTime::decode(decoder)?)
            }
            OptionCode::SolMaxRt => DhcpOption::SolMaxRt(SolMaxRt::decode(decoder)?),
            OptionCode::DomainList => DhcpOption::DomainList(DomainList::decode(decoder)?),
            OptionCode::LqQuery => DhcpOption::LqQuery(LqQuery::decode(decoder)?),
            OptionCode::ClientData => DhcpOption::ClientData(ClientData::decode(decoder)?),
            OptionCode::CltTime => DhcpOption::CltTime(CltTime::decode(decoder)?),
            OptionCode::LqRelayData => DhcpOption::LqRelayData(LqRelayData::decode(decoder)?),
            OptionCode::LqClientLink => DhcpOption::LqClientLink(LqClientLink::decode(decoder)?),
            OptionCode::RelayId => DhcpOption::RelayId(RelayId::decode(decoder)?),
            OptionCode::LinkAddress => DhcpOption::LinkAddress(LinkAddress::decode(decoder)?),
            // not yet implemented
            OptionCode::Unknown(code) => {
                decoder.read_u16()?;
                decoder.read_u16()?;
                DhcpOption::Unknown(UnknownOption {
                    code,
                    data: decoder.read_slice(len)?.to_vec(),
                })
            }
            unimplemented => {
                decoder.read_u16()?;
                decoder.read_u16()?;
                DhcpOption::Unknown(UnknownOption {
                    code: unimplemented.into(),
                    data: decoder.read_slice(len)?.to_vec(),
                })
            }
        })
    }
}
impl Encodable for DhcpOption {
    fn encode(&self, e: &'_ mut Encoder<'_>) -> EncodeResult<()> {
        let code: OptionCode = self.into();
        match self {
            DhcpOption::ClientId(duid) => {
                duid.encode(e)?;
            }
            DhcpOption::ServerId(duid) => {
                duid.encode(e)?;
            }
            DhcpOption::IANA(iana) => {
                iana.encode(e)?;
            }
            DhcpOption::IAPD(iapd) => {
                iapd.encode(e)?;
            }
            DhcpOption::IATA(iata) => {
                iata.encode(e)?;
            }
            DhcpOption::IAAddr(iaaddr) => {
                iaaddr.encode(e)?;
            }
            DhcpOption::ORO(oro) => {
                oro.encode(e)?;
            }
            DhcpOption::Preference(pref) => {
                pref.encode(e)?;
            }
            DhcpOption::ElapsedTime(elapsed) => {
                elapsed.encode(e)?;
            }
            DhcpOption::RelayMsg(msg) => {
                msg.encode(e)?;
            }
            DhcpOption::Auth(auth) => {
                auth.encode(e)?;
            }
            DhcpOption::Unicast(addr) => {
                addr.encode(e)?;
            }
            DhcpOption::StatusCode(status) => {
                status.encode(e)?;
            }
            DhcpOption::RapidCommit(rc) => {
                rc.encode(e)?;
            }
            DhcpOption::UserClass(uc) => {
                uc.encode(e)?;
            }
            DhcpOption::VendorClass(vc) => {
                vc.encode(e)?;
            }
            DhcpOption::VendorOpts(vopts) => {
                vopts.encode(e)?;
            }
            DhcpOption::InterfaceId(id) => {
                id.encode(e)?;
            }
            DhcpOption::ReconfMsg(msg_type) => {
                msg_type.encode(e)?;
            }
            DhcpOption::ReconfAccept(accept) => {
                accept.encode(e)?;
            }
            DhcpOption::SolMaxRt(auth) => {
                auth.encode(e)?;
            }
            DhcpOption::InfMaxRt(auth) => {
                auth.encode(e)?;
            }
            DhcpOption::InformationRefreshTime(auth) => {
                auth.encode(e)?;
            }
            DhcpOption::DNSServers(addrs) => {
                addrs.encode(e)?;
            }
            DhcpOption::DomainList(names) => {
                names.encode(e)?;
            }
            DhcpOption::IAPrefix(iaprefix) => {
                iaprefix.encode(e)?;
            }
            DhcpOption::LqQuery(q) => {
                q.encode(e)?;
            }
            DhcpOption::ClientData(q) => {
                q.encode(e)?;
            }
            DhcpOption::CltTime(q) => {
                q.encode(e)?;
            }
            DhcpOption::LqRelayData(q) => {
                q.encode(e)?;
            }
            DhcpOption::LqClientLink(q) => {
                q.encode(e)?;
            }
            DhcpOption::RelayId(q) => {
                q.encode(e)?;
            }
            DhcpOption::LinkAddress(q) => {
                q.encode(e)?;
            }
            DhcpOption::Unknown(UnknownOption { data, .. }) => {
                e.write_u16(code.into())?;
                e.write_u16(data.len() as u16)?;
                e.write_slice(data)?;
            }
        };
        Ok(())
    }
}

#[inline]
pub(crate) fn first<T, F>(arr: &[T], f: F) -> Option<usize>
where
    F: Fn(&T) -> Ordering,
{
    let mut l = 0;
    let mut r = arr.len() - 1;
    while l <= r {
        let mid = (l + r) >> 1;
        // SAFETY: we know it is within the length
        let mid_cmp = f(unsafe { arr.get_unchecked(mid) });
        let prev_cmp = if mid > 0 {
            f(unsafe { arr.get_unchecked(mid - 1) }) == Ordering::Less
        } else {
            false
        };
        if (mid == 0 || prev_cmp) && mid_cmp == Ordering::Equal {
            return Some(mid);
        } else if mid_cmp == Ordering::Less {
            l = mid + 1;
        } else {
            r = mid - 1;
        }
    }
    None
}

#[inline]
pub(crate) fn last<T, F>(arr: &[T], f: F) -> Option<usize>
where
    F: Fn(&T) -> Ordering,
{
    let n = arr.len();
    let mut l = 0;
    let mut r = n - 1;
    while l <= r {
        let mid = (l + r) >> 1;
        // SAFETY: we know it is within the length
        let mid_cmp = f(unsafe { arr.get_unchecked(mid) });
        let nxt_cmp = if mid < n {
            f(unsafe { arr.get_unchecked(mid + 1) }) == Ordering::Greater
        } else {
            false
        };
        if (mid == n - 1 || nxt_cmp) && mid_cmp == Ordering::Equal {
            return Some(mid);
        } else if mid_cmp == Ordering::Greater {
            r = mid - 1;
        } else {
            l = mid + 1;
        }
    }
    None
}

#[inline]
pub(crate) fn range_binsearch<T, F>(arr: &[T], f: F) -> Option<RangeInclusive<usize>>
where
    F: Fn(&T) -> Ordering,
{
    let first = first(arr, &f)?;
    let last = last(arr, &f)?;
    Some(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_range_binsearch() {
        let arr = vec![0, 1, 1, 1, 1, 4, 6, 7, 9, 9, 10];
        assert_eq!(Some(1..=4), range_binsearch(&arr, |x| x.cmp(&1)));

        let arr = vec![0, 1, 1, 1, 1, 4, 6, 7, 9, 9, 10];
        assert_eq!(Some(0..=0), range_binsearch(&arr, |x| x.cmp(&0)));

        let arr = vec![0, 1, 1, 1, 1, 4, 6, 7, 9, 9, 10];
        assert_eq!(Some(5..=5), range_binsearch(&arr, |x| x.cmp(&4)));

        let arr = vec![1, 2, 2, 2, 2, 3, 4, 7, 8, 8];
        assert_eq!(Some(8..=9), range_binsearch(&arr, |x| x.cmp(&8)));

        let arr = vec![1, 2, 2, 2, 2, 3, 4, 7, 8, 8];
        assert_eq!(Some(1..=4), range_binsearch(&arr, |x| x.cmp(&2)));

        let arr = vec![1, 2, 2, 2, 2, 3, 4, 7, 8, 8];
        assert_eq!(Some(7..=7), range_binsearch(&arr, |x| x.cmp(&7)));
    }
}
