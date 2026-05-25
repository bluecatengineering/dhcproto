use core::fmt;

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
        write!(f, "{self:?}")
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct QueryState(pub u8);

#[allow(non_upper_case_globals)]
impl QueryState {
    pub const Available: Self = Self(1);
    pub const Active: Self = Self(2);
    pub const Expired: Self = Self(3);
    pub const Release: Self = Self(4);
    pub const Abandoned: Self = Self(5);
    pub const Reset: Self = Self(6);
    pub const Remote: Self = Self(7);
    pub const Transitioning: Self = Self(8);
}

impl From<u8> for QueryState {
    fn from(n: u8) -> Self {
        Self(n)
    }
}

impl From<QueryState> for u8 {
    fn from(state: QueryState) -> Self {
        state.0
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Code(pub u8);

#[allow(non_upper_case_globals)]
impl Code {
    pub const Success: Self = Self(0);
    pub const UnspecFail: Self = Self(1);
    pub const QueryTerminated: Self = Self(2);
    pub const MalformedQuery: Self = Self(3);
    pub const NotAllowed: Self = Self(4);
}

impl From<u8> for Code {
    fn from(n: u8) -> Self {
        Self(n)
    }
}

impl From<Code> for u8 {
    fn from(code: Code) -> Self {
        code.0
    }
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
