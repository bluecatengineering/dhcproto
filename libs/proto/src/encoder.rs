use crate::error::{EncodeError, EncodeResult};

/// A trait for types which are deserializable to DHCP binary formats
pub trait Encodable<'a> {
    /// Read the type from the stream
    fn write(&self, enc: &'_ mut Encoder<'a>) -> EncodeResult<usize>;
}

#[derive(Debug)]
pub struct Encoder<'a> {
    buffer: &'a mut Vec<u8>,
    index: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer, index: 0 }
    }

    pub fn write_slice(&mut self, bytes: &[u8]) -> EncodeResult<usize> {
        let count = bytes.len();
        let new_len = self
            .buffer
            .len()
            .checked_add(count)
            .ok_or(EncodeError::AddOverflow)?;
        self.buffer.extend_from_slice(&bytes);
        self.index = new_len;
        Ok(count)
    }

    pub fn write_u8(&mut self, data: u8) -> EncodeResult<usize> {
        self.write_slice(&data.to_be_bytes())
    }
    pub fn write_u16(&mut self, data: u16) -> EncodeResult<usize> {
        self.write_slice(&data.to_be_bytes())
    }
    pub fn write_u32(&mut self, data: u32) -> EncodeResult<usize> {
        self.write_slice(&data.to_be_bytes())
    }
}
