//!
use std::collections::HashMap;

use crate::{Decodable, Encodable};

/// Collection of relay agent information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAgentInformation(HashMap<RelayCode, Info>);

impl Decodable for RelayAgentInformation {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let mut opts = HashMap::new();
        while let Ok(opt) = Info::decode(d) {
            opts.insert(opt.code, opt);
        }
        Ok(RelayAgentInformation(opts))
    }
}

impl Encodable for RelayAgentInformation {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        self.0.iter().try_for_each(|(_, info)| info.encode(e))
    }
}

/// Relay agent information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    code: RelayCode,
    // use just bytes for now
    data: Vec<u8>,
}

impl Info {
    /// return the relay code
    pub fn code(&self) -> RelayCode {
        self.code
    }
    /// return the data for this code
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// take ownership and return the parts of this
    pub fn into_parts(self) -> (RelayCode, Vec<u8>) {
        (self.code, self.data)
    }
}

impl Decodable for Info {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let code = d.read_u8()?.into();
        let len = d.read_u8()? as usize;
        let data = d.read_slice(len)?.to_vec();
        Ok(Self { code, data })
    }
}

impl Encodable for Info {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        e.write_u8(self.code.into())?;
        e.write_u8(self.data.len() as u8)?;
        e.write_slice(&self.data)
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
