use std::fmt;

use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Lease query data source flags
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct DataSourceFlags(u8);

impl fmt::Debug for DataSourceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataSourceFlags")
            .field("remote", &self.remote())
            .finish()
    }
}

impl fmt::Display for DataSourceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DataSourceFlags {
    /// Create new DataSourceFlags from u8
    pub fn new(n: u8) -> Self {
        Self(n)
    }
    /// get the status of the remote flag
    pub fn remote(&self) -> bool {
        (self.0 & 0x01) == 1
    }
    /// set the remote bit, returns a new DataSourceFlags
    pub fn set_remote(mut self) -> Self {
        self.0 |= 0x01;
        self
    }
}

impl From<u8> for DataSourceFlags {
    fn from(n: u8) -> Self {
        Self(n)
    }
}
impl From<DataSourceFlags> for u8 {
    fn from(f: DataSourceFlags) -> Self {
        f.0
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive)]
#[num_enum(u8)]
pub enum QueryState {
    #[num_enum(num = 1)]
    Available,
    #[num_enum(num = 2)]
    Active,
    #[num_enum(num = 3)]
    Expired,
    #[num_enum(num = 4)]
    Release,
    #[num_enum(num = 5)]
    Abandoned,
    #[num_enum(num = 6)]
    Reset,
    #[num_enum(num = 7)]
    Remote,
    #[num_enum(num = 8)]
    Transitioning,
    #[num_enum(catch_all)]
    Unknown(u8),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive)]
#[num_enum(u8)]
pub enum Code {
    #[num_enum(num = 0)]
    Success,
    #[num_enum(num = 1)]
    UnspecFail,
    #[num_enum(num = 2)]
    QueryTerminated,
    #[num_enum(num = 3)]
    MalformedQuery,
    #[num_enum(num = 4)]
    NotAllowed,
    #[num_enum(catch_all)]
    Unknown(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datasourceflags() {
        let flag = DataSourceFlags::default();
        assert_eq!(flag.0, 0);
        let flag = flag.set_remote();
        assert_eq!(flag.0, 0x01);
        assert!(flag.remote());

        let flag = DataSourceFlags::new(0x80).set_remote();
        assert_eq!(flag.0, 0x81);
    }
}
