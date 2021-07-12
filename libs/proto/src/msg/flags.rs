#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    /// get the status of the broadcast flag
    pub fn broadcast(&self) -> bool {
        (self.0 & 0x8000) >> 15 == 1
    }
}
