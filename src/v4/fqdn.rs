use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents available flags on message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
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
        (self.0 & 0x08) >> (u8::BITS - 1) == 1
    }
    /// set the n bit
    pub fn set_n(mut self) -> Self {
        self.0 |= 0x08;
        self
    }
    /// get the status of the e flag
    pub fn e(&self) -> bool {
        (self.0 & 0x04) >> (u8::BITS - 1) == 1
    }
    /// set the e bit
    pub fn set_e(mut self) -> Self {
        self.0 |= 0x04;
        self
    }
    /// get the status of the o flag
    pub fn o(&self) -> bool {
        (self.0 & 0x02) >> (u8::BITS - 1) == 1
    }
    /// set the o bit
    pub fn set_o(mut self) -> Self {
        self.0 |= 0x02;
        self
    }
    /// get the status of the s flag
    pub fn s(&self) -> bool {
        (self.0 & 0x01) >> (u8::BITS - 1) == 1
    }
    /// set the s bit
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
    fn test_n() {
        let flag = FqdnFlags::default();
        assert_eq!(flag.0, 0);
        let flag = flag.set_n();
        assert_eq!(flag.0, 0x80);
        assert!(flag.n());

        let flag = FqdnFlags::new(0x40).set_s();
        assert_eq!(flag.0, 0x41);
    }
}
