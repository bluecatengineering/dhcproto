use std::net::Ipv6Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::v6::HType;
use crate::Encoder;

/// Duid helper type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duid(Vec<u8>);
// TODO: define specific duid types

impl Duid {
    /// new DUID link layer address with time
    pub fn link_layer_time(htype: HType, time: u32, addr: Ipv6Addr) -> Self {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.write_u16(1).unwrap(); // duid type
        e.write_u16(u16::from(htype)).unwrap();
        e.write_u32(time).unwrap();
        e.write_u128(addr.into()).unwrap();
        Self(buf)
    }
    /// new DUID enterprise number
    pub fn enterprise(enterprise: u32, id: &[u8]) -> Self {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.write_u16(2).unwrap(); // duid type
        e.write_u32(enterprise).unwrap();
        e.write_slice(id).unwrap();
        Self(buf)
    }
    /// new link layer DUID
    pub fn link_layer(htype: HType, addr: Ipv6Addr) -> Self {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.write_u16(3).unwrap(); // duid type
        e.write_u16(u16::from(htype)).unwrap();
        e.write_u128(addr.into()).unwrap();
        Self(buf)
    }
    /// new DUID-UUID
    /// `uuid` must be 16 bytes long
    pub fn uuid(uuid: &[u8]) -> Self {
        assert!(uuid.len() == 16);
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.write_u16(4).unwrap(); // duid type
        e.write_slice(uuid).unwrap();
        Self(buf)
    }
    /// create a DUID of unknown type
    pub fn unknown(duid: &[u8]) -> Self {
        Self(duid.to_vec())
    }
    /// total length of contained DUID
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// is contained DUID empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for Duid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Duid {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}
