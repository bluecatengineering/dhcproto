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
        use QueryState as Q;
        match state {
            Q::Available => 1,
            Q::Active => 2,
            Q::Expired => 3,
            Q::Release => 4,
            Q::Abandoned => 5,
            Q::Reset => 6,
            Q::Remote => 7,
            Q::Transitioning => 8,
            Q::Unknown(code) => code,
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
        use Code as C;
        match code {
            C::Success => 0,
            C::UnspecFail => 1,
            C::QueryTerminated => 2,
            C::MalformedQuery => 3,
            C::NotAllowed => 4,
            C::Unknown(code) => code,
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
