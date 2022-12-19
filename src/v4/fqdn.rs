use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Domain;

/// A client FQDN
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientFQDN {
    pub(crate) flags: FqdnFlags,
    pub(crate) r1: u8,
    pub(crate) r2: u8,
    pub(crate) domain: Domain,
}

impl ClientFQDN {
    // creates a new client fqdn setting the rcode1/rcode2 fields to 255
    pub fn new(flags: FqdnFlags, domain: Domain) -> Self {
        Self {
            flags,
            r1: 0xFF,
            r2: 0xFF,
            domain,
        }
    }
    pub fn flags(&self) -> FqdnFlags {
        self.flags
    }
    pub fn set_flags(&mut self, flags: FqdnFlags) -> &mut Self {
        self.flags = flags;
        self
    }
    pub fn r1(&self) -> u8 {
        self.r1
    }
    pub fn set_r1(&mut self, rcode1: u8) -> &mut Self {
        self.r1 = rcode1;
        self
    }
    pub fn r2(&self) -> u8 {
        self.r2
    }
    pub fn set_r2(&mut self, rcode2: u8) -> &mut Self {
        self.r2 = rcode2;
        self
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
    pub fn set_domain(&mut self, domain: Domain) -> &mut Self {
        self.domain = domain;
        self
    }
    pub fn domain_mut(&mut self) -> &mut Domain {
        &mut self.domain
    }
}

/// Represents available flags on message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Default, Clone, PartialEq, Eq, Hash)]
pub struct FqdnFlags(u8);

impl fmt::Debug for FqdnFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FqdnFlags")
            .field("N", &self.n())
            .field("E", &self.e())
            .field("O", &self.o())
            .field("S", &self.s())
            .finish()
    }
}

impl fmt::Display for FqdnFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FqdnFlags {
    /// Create new FqdnFlags from u8
    pub fn new(n: u8) -> Self {
        Self(n)
    }
    /// get the status of the n flag
    pub fn n(&self) -> bool {
        (self.0 & 0x08) > 0
    }
    /// set the n bit, whether the server SHOULD NOT perform any DNS updates.
    /// clients set this to 0 to indicate the server SHOULD update, and 1
    /// to indicate it SHOULD NOT
    pub fn set_n(mut self) -> Self {
        self.0 |= 0x08;
        self
    }
    /// get the status of the e flag
    pub fn e(&self) -> bool {
        (self.0 & 0x04) > 0
    }
    /// set the e bit
    pub fn set_e(mut self) -> Self {
        self.0 |= 0x04;
        self
    }
    /// get the status of the o flag
    pub fn o(&self) -> bool {
        (self.0 & 0x02) > 0
    }
    /// set the o bit
    pub fn set_o(mut self) -> Self {
        self.0 |= 0x02;
        self
    }
    /// get the status of the s flag
    pub fn s(&self) -> bool {
        (self.0 & 0x01) > 0
    }
    /// set the s bit. Indicates whether the server should perform an A RR update
    pub fn set_s(mut self) -> Self {
        self.0 |= 0x01;
        self
    }
}

impl From<u8> for FqdnFlags {
    fn from(n: u8) -> Self {
        Self(n)
    }
}
impl From<FqdnFlags> for u8 {
    fn from(f: FqdnFlags) -> Self {
        f.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fqdn_flags() {
        let flag = FqdnFlags::default();
        assert_eq!(flag.0, 0);
        let flag = flag.set_n();
        assert!(flag.n());
        assert_eq!(flag.0, 0x08);

        let flag = FqdnFlags::new(0x40).set_s();
        assert!(!flag.e());
        assert!(flag.s());
        assert!(!flag.n());
        assert!(!flag.o());
        assert_eq!(flag.0, 0x41);
        let flag = flag.set_e();
        assert!(flag.e() && flag.s());

        let flag = FqdnFlags::default().set_e();
        assert!(flag.e());
        assert_eq!(flag.0, 0x04);
    }
}
