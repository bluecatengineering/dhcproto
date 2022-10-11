#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

use trust_dns_proto::{
    rr::Name,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

use std::{cmp::Ordering, net::Ipv6Addr, ops::RangeInclusive};

pub use crate::Domain;
use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v6::{Duid, MessageType, OROCode, OptionCode, RelayMessage},
};
//helper macro for implementing sub-options (IANAOptions, ect)
//useage: option_builder!(IANAOption, IANAOptions, DhcpOption, IAAddr, StatusCode);
//        option_builder!(name      , names      , master    , subname...        );
macro_rules! option_builder{
    ($name: ident, $names: ident, $mastername: ident, $($subnames: ident),*) => {
		#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
		#[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $(
				$subnames($subnames),
			)*
				Unknown($mastername),
        }
		$(
			impl From<$subnames> for $name {
				fn from(sc: $subnames) -> Self{
					$name :: $subnames(sc)
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
			/// insert a new option into the list of opts
			pub fn insert<T: Into<$name>>(&mut self, opt: T){
				self.0.push(opt.into())
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
    ClientId(Vec<u8>), // should duid for this be bytes or string?
    /// 2 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.3>
    ServerId(Vec<u8>),
    /// 3 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.4>
    IANA(IANA),
    /// 4 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.5>
    IATA(IATA),
    /// 5 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.6>
    IAAddr(IAAddr),
    /// 6 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.7>
    ORO(ORO),
    /// 7 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.8>
    Preference(u8),
    /// 8 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.9>
    /// Elapsed time in millis
    ElapsedTime(u16),
    /// 9 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.10>
    RelayMsg(RelayMessage),
    /// 11 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.11>
    Auth(Auth),
    /// 12 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.12>
    Unicast(Ipv6Addr),
    /// 13 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.13>
    StatusCode(StatusCode),
    /// 14 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.14>
    RapidCommit,
    /// 15 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.15>
    UserClass(UserClass),
    /// 16 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.16>
    VendorClass(VendorClass),
    /// 17 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.17>
    VendorOpts(VendorOpts),
    /// 18 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.18>
    InterfaceId(Vec<u8>),
    /// 19 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.19>
    ReconfMsg(MessageType),
    /// 20 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.20>
    ReconfAccept,
    /// 23 - <https://datatracker.ietf.org/doc/html/rfc3646>
    DNSServers(Vec<Ipv6Addr>),
    /// 24 - <https://datatracker.ietf.org/doc/html/rfc3646>
    DomainList(Vec<Domain>),
    /// 25 - <https://datatracker.ietf.org/doc/html/rfc8415#section-21.21>
    IAPD(IAPD),
    /// 26 - <https://datatracker.ietf.org/doc/html/rfc3633#section-10>
    IAPrefix(IAPrefix),
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

/// wrapper around interface id
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceId {
    pub id: String,
}

/// vendor options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOpts {
    pub num: u32,
    // encapsulated options values
    pub opts: DhcpOptions,
}

/// vendor class
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VendorClass {
    pub num: u32,
    pub data: Vec<Vec<u8>>,
    // each item in data is [len (2 bytes) | data]
}

/// user class
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserClass {
    pub data: Vec<Vec<u8>>,
    // each item in data is [len (2 bytes) | data]
}

#[inline]
fn decode_data(decoder: &'_ mut Decoder<'_>) -> Vec<Vec<u8>> {
    let mut data = Vec::new();
    while let Ok(len) = decoder.read_u16() {
        // if we can read the len and the string
        match decoder.read_slice(len as usize) {
            Ok(s) => data.push(s.to_vec()),
            // push, otherwise stop
            _ => break,
        }
    }
    data
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
            OptionCode::ClientId => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::ClientId(decoder.read_slice(len)?.to_vec())
            }
            OptionCode::ServerId => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::ServerId(decoder.read_slice(len)?.to_vec())
            }
            OptionCode::IANA => {
                DhcpOption::IANA(IANA::decode(decoder)?)
            }
            OptionCode::IATA => {
                DhcpOption::IATA(IATA::decode(decoder)?)
            }
            OptionCode::IAAddr => {
                
                DhcpOption::IAAddr(IAAddr::decode(decoder)?)
            }
            OptionCode::ORO => {
                DhcpOption::ORO(ORO::decode(decoder)?)
            }
            OptionCode::Preference => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::Preference(decoder.read_u8()?)
            }
            OptionCode::ElapsedTime => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::ElapsedTime(decoder.read_u16()?)
            }
            OptionCode::RelayMsg => {
				decoder.read_u16()?;decoder.read_u16()?;
                let mut relay_dec = Decoder::new(decoder.read_slice(len)?);
                DhcpOption::RelayMsg(RelayMessage::decode(&mut relay_dec)?)
            }
            OptionCode::Auth => {
                DhcpOption::Auth(Auth::decode(decoder)?)
            }
            OptionCode::Unicast => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::Unicast(decoder.read::<16>()?.into())
            }
            OptionCode::StatusCode => {
                DhcpOption::StatusCode(StatusCode::decode(decoder)?)
            }
            OptionCode::RapidCommit => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::RapidCommit
            }
            OptionCode::UserClass => {
				decoder.read_u16()?;decoder.read_u16()?;
                let buf = decoder.read_slice(len)?;
                DhcpOption::UserClass(UserClass {
                    data: decode_data(&mut Decoder::new(buf)),
                })
            }
            OptionCode::VendorClass => {
				decoder.read_u16()?;decoder.read_u16()?;
                let num = decoder.read_u32()?;
                let buf = decoder.read_slice(len - 4)?;
                DhcpOption::VendorClass(VendorClass {
                    num,
                    data: decode_data(&mut Decoder::new(buf)),
                })
            }
            OptionCode::VendorOpts => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::VendorOpts(VendorOpts {
                    num: decoder.read_u32()?,
                    opts: {
                        let mut opt_decoder = Decoder::new(decoder.read_slice(len - 4)?);
                        DhcpOptions::decode(&mut opt_decoder)?
                    },
                })
            }
            OptionCode::InterfaceId => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::InterfaceId(decoder.read_slice(len)?.to_vec())
            }
            OptionCode::ReconfMsg => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::ReconfMsg(decoder.read_u8()?.into())
            }
            OptionCode::ReconfAccept => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::ReconfAccept
            }
            OptionCode::DNSServers => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::DNSServers(decoder.read_ipv6s(len)?)
            }
            OptionCode::IAPD => {
                DhcpOption::IAPD(IAPD::decode(decoder)?)
            }
            OptionCode::IAPrefix => {
                DhcpOption::IAPrefix(IAPrefix::decode(decoder)?)
            }
            OptionCode::DomainList => {
				decoder.read_u16()?;decoder.read_u16()?;
                let mut name_decoder = BinDecoder::new(decoder.read_slice(len as usize)?);
                let mut names = Vec::new();
                while let Ok(name) = Name::read(&mut name_decoder) {
                    names.push(Domain(name));
                }

                DhcpOption::DomainList(names)
            }
            // not yet implemented
            OptionCode::Unknown(code) => {
				decoder.read_u16()?;decoder.read_u16()?;
                DhcpOption::Unknown(UnknownOption {
                    code,
                    data: decoder.read_slice(len)?.to_vec(),
                })
            }
            unimplemented => {
				decoder.read_u16()?;decoder.read_u16()?;
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
            DhcpOption::ClientId(duid) | DhcpOption::ServerId(duid) => {
				e.write_u16(code.into())?;
                e.write_u16(duid.len() as u16)?;
                e.write_slice(duid)?;
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
				e.write_u16(code.into())?;
                e.write_u16(1)?;
                e.write_u8(*pref)?;
            }
            DhcpOption::ElapsedTime(elapsed) => {
				e.write_u16(code.into())?;
                e.write_u16(2)?;
                e.write_u16(*elapsed)?;
            }
            DhcpOption::RelayMsg(msg) => {
				e.write_u16(code.into())?;
                let mut buf = Vec::new();
                let mut relay_enc = Encoder::new(&mut buf);
                msg.encode(&mut relay_enc)?;

                e.write_u16(buf.len() as u16)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::Auth(auth) => {
				auth.encode(e)?;
            }
            DhcpOption::Unicast(addr) => {
				e.write_u16(code.into())?;
                e.write_u16(16)?;
                e.write_u128((*addr).into())?;
            }
            DhcpOption::StatusCode(status) => {
				status.encode(e)?;
            }
            DhcpOption::RapidCommit => {
				e.write_u16(code.into())?;
                e.write_u16(0)?;
            }
            DhcpOption::UserClass(UserClass { data }) => {
				e.write_u16(code.into())?;
                e.write_u16(data.len() as u16)?;
                for s in data {
                    e.write_u16(s.len() as u16)?;
                    e.write_slice(s)?;
                }
            }
            DhcpOption::VendorClass(VendorClass { num, data }) => {
				e.write_u16(code.into())?;
                e.write_u16(4 + data.len() as u16)?;
                e.write_u32(*num)?;
                for s in data {
                    e.write_u16(s.len() as u16)?;
                    e.write_slice(s)?;
                }
            }
            DhcpOption::VendorOpts(VendorOpts { num, opts }) => {
				e.write_u16(code.into())?;
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                opts.encode(&mut opt_enc)?;
                // buf now has total len
                e.write_u16(4 + buf.len() as u16)?;
                e.write_u32(*num)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::InterfaceId(id) => {
				e.write_u16(code.into())?;
                e.write_u16(id.len() as u16)?;
                e.write_slice(id)?;
            }
            DhcpOption::ReconfMsg(msg_type) => {
				e.write_u16(code.into())?;
                e.write_u16(1)?;
                e.write_u8((*msg_type).into())?;
            }
            DhcpOption::ReconfAccept => {
				e.write_u16(code.into())?;
                e.write_u16(0)?;
            }
            DhcpOption::DNSServers(addrs) => {
				e.write_u16(code.into())?;
                e.write_u16(addrs.len() as u16 * 16)?;
                for addr in addrs {
                    e.write_u128((*addr).into())?;
                }
            }
            DhcpOption::DomainList(names) => {
				e.write_u16(code.into())?;
                let mut buf = Vec::new();
                let mut name_encoder = BinEncoder::new(&mut buf);
                for name in names {
                    name.0.emit(&mut name_encoder)?;
                }
                e.write_u16(buf.len() as u16)?;
                e.write_slice(&buf)?;
            }
            DhcpOption::IAPrefix(iaprefix) => {
				iaprefix.encode(e)?;
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
fn first<T, F>(arr: &[T], f: F) -> Option<usize>
where
    T: Ord,
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
fn last<T, F>(arr: &[T], f: F) -> Option<usize>
where
    T: Ord,
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
fn range_binsearch<T, F>(arr: &[T], f: F) -> Option<RangeInclusive<usize>>
where
    T: Ord,
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
