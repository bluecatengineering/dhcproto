use std::fmt;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryState {
    Available,
    Active,
    Expired,
    Release,
    Abandoned,
    Reset,
    Remote,
    Transitioning,
    Unknown(u8),
}

impl From<u8> for QueryState {
    fn from(n: u8) -> Self {
        use QueryState::*;
        match n {
            1 => Available,
            2 => Active,
            3 => Expired,
            4 => Release,
            5 => Abandoned,
            6 => Reset,
            7 => Remote,
            8 => Transitioning,
            _ => Unknown(n),
        }
    }
}

impl From<QueryState> for u8 {
    fn from(state: QueryState) -> Self {
        use QueryState::*;
        match state {
            Available => 1,
            Active => 2,
            Expired => 3,
            Release => 4,
            Abandoned => 5,
            Reset => 6,
            Remote => 7,
            Transitioning => 8,
            Unknown(code) => code,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    Success,
    UnspecFail,
    QueryTerminated,
    MalformedQuery,
    NotAllowed,
    Unknown(u8),
}

impl From<u8> for Code {
    fn from(n: u8) -> Self {
        use Code::*;
        match n {
            0 => Success,
            1 => UnspecFail,
            2 => QueryTerminated,
            3 => MalformedQuery,
            4 => NotAllowed,
            _ => Unknown(n),
        }
    }
}

impl From<Code> for u8 {
    fn from(code: Code) -> Self {
        use Code::*;
        match code {
            Success => 0,
            UnspecFail => 1,
            QueryTerminated => 2,
            MalformedQuery => 3,
            NotAllowed => 4,
            Unknown(code) => code,
        }
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
