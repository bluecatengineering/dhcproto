//!
use std::{
    collections::{hash_map, HashMap},
    fmt,
    net::Ipv4Addr,
};

use crate::{Decodable, Encodable};

/// Collection of relay agent information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAgentInformation(HashMap<RelayCode, RelayInfo>);

impl RelayAgentInformation {
    /// Get the data for a particular RelayCode
    pub fn get(&self, code: RelayCode) -> Option<&RelayInfo> {
        self.0.get(&code)
    }
    /// Get the mutable data for a particular OptionCode
    pub fn get_mut(&mut self, code: RelayCode) -> Option<&mut RelayInfo> {
        self.0.get_mut(&code)
    }
    /// remove option
    pub fn remove(&mut self, code: RelayCode) -> Option<RelayInfo> {
        self.0.remove(&code)
    }
    /// insert a new option
    pub fn insert(&mut self, info: RelayInfo) -> Option<RelayInfo> {
        self.0.insert((&info).into(), info)
    }
    /// iterate over entries
    pub fn iter(&self) -> hash_map::Iter<'_, RelayCode, RelayInfo> {
        self.0.iter()
    }
    /// iterate mutably over entries
    pub fn iter_mut(&mut self) -> hash_map::IterMut<'_, RelayCode, RelayInfo> {
        self.0.iter_mut()
    }
}

impl Decodable for RelayAgentInformation {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let mut opts = HashMap::new();
        while let Ok(opt) = RelayInfo::decode(d) {
            opts.insert(RelayCode::from(&opt), opt);
        }
        Ok(RelayAgentInformation(opts))
    }
}

impl Encodable for RelayAgentInformation {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        self.0.iter().try_for_each(|(_, info)| info.encode(e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayInfo {
    /// 1 - <https://datatracker.ietf.org/doc/html/rfc3046>
    AgentCircuitId(Vec<u8>),
    /// 2 - <https://datatracker.ietf.org/doc/html/rfc3046>
    AgentRemoteId(Vec<u8>),
    /// 3 - <https://datatracker.ietf.org/doc/html/rfc3256>
    DocsisDeviceClass(u32),
    /// 5 - <https://datatracker.ietf.org/doc/html/rfc3527>
    LinkSelection(Ipv4Addr),
    /// 6 - <https://datatracker.ietf.org/doc/html/rfc3993#section-3.1>
    SubscriberId(Vec<u8>),
    /// 10 - <https://datatracker.ietf.org/doc/html/rfc5010#section-3>
    RelayAgentFlags(RelayFlags),
    /// 11 - <https://datatracker.ietf.org/doc/html/rfc5107#section-4>
    ServerIdentifierOverride(Ipv4Addr),
    Unknown(UnknownInfo),
    // TODO: not tackling this at the moment
    // 7 - <https://datatracker.ietf.org/doc/html/rfc4014>
    // RadiusAttributes,
    // 8 - <https://datatracker.ietf.org/doc/html/rfc4030#section-4>
    // 9
    // VendorSpecificInformation(Vec<u8>),
    // Authentication(Authentication),
    // 151 - <https://datatracker.ietf.org/doc/html/rfc6607>
    // VirtualSubnet(VirtualSubnet),
    // 152
    // VirtualSubnetControl(u8),
}

impl Decodable for RelayInfo {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        use RelayInfo::*;
        // read the code first, determines the variant

        // pad has no length, so we can't read len up here
        Ok(match d.read_u8()?.into() {
            RelayCode::AgentCircuitId => {
                let len = d.read_u8()? as usize;
                let data = d.read_slice(len)?.to_vec();
                AgentCircuitId(data)
            }
            RelayCode::AgentRemoteId => {
                let len = d.read_u8()? as usize;
                let data = d.read_slice(len)?.to_vec();
                AgentCircuitId(data)
            }
            RelayCode::DocsisDeviceClass => {
                let device_id = d.read_u32()?;
                DocsisDeviceClass(device_id)
            }
            RelayCode::LinkSelection => {
                let len = d.read_u8()? as usize;
                LinkSelection(d.read_ipv4(len)?)
            }
            RelayCode::SubscriberId => {
                let len = d.read_u8()? as usize;
                let data = d.read_slice(len)?.to_vec();
                SubscriberId(data)
            }
            RelayCode::RelayAgentFlags => {
                let _len = d.read_u8()?;
                let flags = d.read_u8()?;
                RelayAgentFlags(flags.into())
            }
            RelayCode::ServerIdentifierOverride => {
                let len = d.read_u8()? as usize;
                ServerIdentifierOverride(d.read_ipv4(len)?)
            }
            // we have codes for these but not full type definitions yet
            code
            @
            (RelayCode::Authentication
            | RelayCode::VirtualSubnet
            | RelayCode::VirtualSubnetControl
            | RelayCode::RadiusAttributes
            | RelayCode::VendorSpecificInformation) => {
                let length = d.read_u8()?;
                let bytes = d.read_slice(length as usize)?.to_vec();
                Unknown(UnknownInfo {
                    code: code.into(),
                    bytes,
                })
            }
            // not yet implemented
            RelayCode::Unknown(code) => {
                let length = d.read_u8()?;
                let bytes = d.read_slice(length as usize)?.to_vec();
                Unknown(UnknownInfo { code, bytes })
            }
        })
    }
}

// pub struct VirtualSubnet {
//     code: VssInfo,
// }

// pub enum VssInfo {
//     NvtVpnId,
//     VpnId,
//     Unassigned,
//     GlobalVpn,
// }

// impl From<u8> for VssInfo {
//     fn from(n: u8) -> Self {
//         match n {
//             0 => VssInfo::NvtVpnId,
//             1 => VssInfo::VpnId,
//             2..=254 => VssInfo::Unassigned,
//             255 => VssInfo::GlobalVpn,
//         }
//     }
// }

impl Encodable for RelayInfo {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        use RelayInfo::*;

        let code: RelayCode = self.into();

        e.write_u8(code.into())?;
        match self {
            AgentCircuitId(id) | AgentRemoteId(id) | SubscriberId(id) => {
                // length of bytes stored in Vec
                e.write_u8(id.len() as u8)?;
                e.write_slice(id)?
            }
            DocsisDeviceClass(n) => {
                e.write_u8(4)?;
                e.write_u32(*n)?
            }
            LinkSelection(addr) | ServerIdentifierOverride(addr) => {
                e.write_u8(4)?;
                e.write_u32((*addr).into())?
            }
            RelayAgentFlags(flags) => {
                e.write_u8(0)?;
                e.write_u8((*flags).into())?
            }
            // not yet implemented
            Unknown(opt) => {
                // length of bytes stored in Vec
                e.write_u8(opt.bytes.len() as u8)?;
                e.write_slice(&opt.bytes)?
            }
        };
        Ok(())
    }
}
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct RelayFlags(u8);

impl fmt::Debug for RelayFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayFlags")
            .field("unicast", &self.unicast())
            .finish()
    }
}

impl fmt::Display for RelayFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl RelayFlags {
    /// Create new RelayFlags from u8
    pub fn new(n: u8) -> Self {
        Self(n)
    }
    /// get the status of the unicast flag
    pub fn unicast(&self) -> bool {
        (self.0 & 0x80) >> 7 == 1
    }
    /// set the unicast bit, returns a new Flags
    pub fn set_unicast(mut self) -> Self {
        self.0 |= 0x80;
        self
    }
}

impl From<u8> for RelayFlags {
    fn from(n: u8) -> Self {
        Self(n)
    }
}
impl From<RelayFlags> for u8 {
    fn from(f: RelayFlags) -> Self {
        f.0
    }
}

/// An as-of-yet unimplemented relay info
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownInfo {
    code: u8,
    bytes: Vec<u8>,
}

impl UnknownInfo {
    /// return the relay code
    pub fn code(&self) -> RelayCode {
        self.code.into()
    }
    /// return the data for this code
    pub fn data(&self) -> &[u8] {
        &self.bytes
    }
    /// take ownership and return the parts of this
    pub fn into_parts(self) -> (RelayCode, Vec<u8>) {
        (self.code.into(), self.bytes)
    }
}

/// relay code, represented as a u8
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RelayCode {
    AgentCircuitId,
    AgentRemoteId,
    DocsisDeviceClass,
    LinkSelection,
    SubscriberId,
    RadiusAttributes,
    Authentication,
    VendorSpecificInformation,
    RelayAgentFlags,
    ServerIdentifierOverride,
    VirtualSubnet,
    VirtualSubnetControl,
    /// unknown/unimplemented message type
    Unknown(u8),
}

impl From<u8> for RelayCode {
    fn from(n: u8) -> Self {
        use RelayCode::*;
        match n {
            1 => AgentCircuitId,
            2 => AgentRemoteId,
            4 => DocsisDeviceClass,
            5 => LinkSelection,
            6 => SubscriberId,
            7 => RadiusAttributes,
            8 => Authentication,
            9 => VendorSpecificInformation,
            10 => RelayAgentFlags,
            11 => ServerIdentifierOverride,
            151 => VirtualSubnet,
            152 => VirtualSubnetControl,
            _ => Unknown(n),
        }
    }
}
impl From<RelayCode> for u8 {
    fn from(code: RelayCode) -> Self {
        use RelayCode::*;
        match code {
            AgentCircuitId => 1,
            AgentRemoteId => 2,
            DocsisDeviceClass => 4,
            LinkSelection => 5,
            SubscriberId => 6,
            RadiusAttributes => 7,
            Authentication => 8,
            VendorSpecificInformation => 9,
            RelayAgentFlags => 10,
            ServerIdentifierOverride => 11,
            VirtualSubnet => 151,
            VirtualSubnetControl => 152,
            Unknown(n) => n,
        }
    }
}

impl From<&RelayInfo> for RelayCode {
    fn from(info: &RelayInfo) -> Self {
        match info {
            RelayInfo::AgentCircuitId(_) => RelayCode::AgentCircuitId,
            RelayInfo::AgentRemoteId(_) => RelayCode::AgentRemoteId,
            RelayInfo::DocsisDeviceClass(_) => RelayCode::DocsisDeviceClass,
            RelayInfo::LinkSelection(_) => RelayCode::LinkSelection,
            RelayInfo::SubscriberId(_) => RelayCode::SubscriberId,
            RelayInfo::RelayAgentFlags(_) => RelayCode::RelayAgentFlags,
            RelayInfo::ServerIdentifierOverride(_) => RelayCode::ServerIdentifierOverride,
            RelayInfo::Unknown(unknown) => RelayCode::Unknown(unknown.code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn test_unicast() {
        let flag = RelayFlags::default();
        assert_eq!(flag.0, 0);
        let flag = flag.set_unicast();
        assert_eq!(flag.0, 0x80);

        let flag = RelayFlags::new(0x00).set_unicast();
        assert_eq!(flag.0, 0x80);
        assert!(flag.unicast());
    }

    fn test_opt(opt: RelayInfo, actual: Vec<u8>) -> Result<()> {
        let mut out = vec![];
        let mut enc = crate::Encoder::new(&mut out);
        opt.encode(&mut enc)?;
        println!("{:?}", enc.buffer());
        assert_eq!(out, actual);

        let buf = RelayInfo::decode(&mut crate::Decoder::new(&out))?;
        assert_eq!(buf, opt);
        Ok(())
    }
    // #[test]
    // fn test_opts() -> Result<()> {
    //     let input = binput();
    //     println!("{:?}", input);
    //     let opts = DhcpOptions::decode(&mut Decoder::new(&input))?;

    //     let mut output = Vec::new();
    //     let _len = opts.encode(&mut Encoder::new(&mut output))?;
    //     // not comparing len as we don't add PAD bytes
    //     // assert_eq!(input.len(), len);
    //     Ok(())
    // }

    #[test]
    fn test_ip() -> Result<()> {
        test_opt(
            RelayInfo::LinkSelection("192.168.0.1".parse::<Ipv4Addr>().unwrap()),
            vec![5, 4, 192, 168, 0, 1],
        )?;
        Ok(())
    }
    #[test]
    fn test_str() -> Result<()> {
        test_opt(
            RelayInfo::AgentCircuitId(vec![0, 1, 2, 3, 4]),
            vec![1, 5, 0, 1, 2, 3, 4],
        )?;

        Ok(())
    }
}
