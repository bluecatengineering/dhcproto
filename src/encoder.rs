//! Encodable trait & Encoder
use crate::error::{EncodeError, EncodeResult};

/// A trait for types which are deserializable to DHCP binary formats
pub trait Encodable {
    /// encode type to buffer in Encoder
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()>;

    /// encode this type into its binary form in a new `Vec`
    fn to_vec(&self) -> EncodeResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(512);
        let mut encoder = Encoder::new(&mut buffer);
        self.encode(&mut encoder)?;
        Ok(buffer)
    }
}

/// Encoder type, holds a mut ref to a buffer
/// that it will write data to and an offset
/// of the next position to write.
///
/// This will start writing from the beginning of the buffer, *not* from the end.
/// The buffer will be grown as needed.
#[derive(Debug)]
pub struct Encoder<'a> {
    buffer: &'a mut Vec<u8>,
    offset: usize,
}

impl<'a> Encoder<'a> {
    /// Create a new Encoder from a mutable buffer
    pub fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer, offset: 0 }
    }

    /// Get a reference to the underlying buffer
    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that has been filled.
    pub fn buffer_filled(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    /// Returns the number of bytes that have been written to the buffer.
    pub fn len_filled(&self) -> usize {
        self.offset
    }

    /// write bytes to buffer
    /// Return:
    ///     number of bytes written
    pub fn write_slice(&mut self, bytes: &[u8]) -> EncodeResult<()> {
        let additional = bytes.len();
        // space already reserved, we may not need this
        if self.offset + additional <= self.buffer.len() {
            // if self.offset == self.buffer.len() indexing can panic
            for (byte, b) in self.buffer[self.offset..].iter_mut().zip(bytes.iter()) {
                *byte = *b;
            }
        } else {
            let expected_len = self.buffer.len() + additional;
            self.buffer.reserve(additional);
            self.buffer.extend_from_slice(bytes);

            debug_assert!(self.buffer.len() == expected_len);
        }

        let index = self
            .offset
            .checked_add(additional)
            .ok_or(EncodeError::AddOverflow)?;
        self.offset = index;
        Ok(())
    }

    /// Write const number of bytes to buffer
    pub fn write<const N: usize>(&mut self, bytes: [u8; N]) -> EncodeResult<()> {
        // TODO: refactor this and above method?
        // only difference is zip & extend
        let additional = bytes.len();
        // space already reserved, we may not need this
        if self.offset + additional <= self.buffer.len() {
            // if self.offset == self.buffer.len() indexing can panic
            for (byte, b) in self.buffer[self.offset..].iter_mut().zip(bytes) {
                *byte = b;
            }
        } else {
            let expected_len = self.buffer.len() + additional;
            self.buffer.reserve(additional);
            self.buffer.extend(bytes);
            debug_assert!(self.buffer.len() == expected_len);
        }

        let index = self
            .offset
            .checked_add(additional)
            .ok_or(EncodeError::AddOverflow)?;
        self.offset = index;
        Ok(())
    }

    /// write a u8
    pub fn write_u8(&mut self, data: u8) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// write a u16
    pub fn write_u16(&mut self, data: u16) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// write a u32
    pub fn write_u32(&mut self, data: u32) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// write a u128
    pub fn write_u128(&mut self, data: u128) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// write a u64
    pub fn write_u64(&mut self, data: u64) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// write a i32
    pub fn write_i32(&mut self, data: i32) -> EncodeResult<()> {
        self.write(data.to_be_bytes())
    }
    /// Writes bytes to buffer and pads with 0 bytes up to some fill_len
    ///
    /// Returns
    ///    Err - if bytes.len() is greater then fill_len
    pub fn write_fill_bytes(&mut self, bytes: &[u8], fill_len: usize) -> EncodeResult<()> {
        if bytes.len() > fill_len {
            return Err(EncodeError::StringSizeTooBig { len: bytes.len() });
        }
        let nul_len = fill_len - bytes.len();
        self.write_slice(bytes)?;
        for _ in 0..nul_len {
            self.write_u8(0)?;
        }
        Ok(())
    }
    /// Writes value to buffer and pads with 0 bytes up to some fill_len
    /// if String is None then write fill_len 0 bytes
    ///
    /// Returns
    ///    Err - if bytes.len() is greater then fill_len
    pub fn write_fill<T: AsRef<[u8]>>(
        &mut self,
        s: &Option<T>,
        fill_len: usize,
    ) -> EncodeResult<()> {
        match s {
            Some(sname) => {
                let bytes = sname.as_ref();
                self.write_fill_bytes(bytes, fill_len)?;
            }
            None => {
                // should we keep some static [0;64] arrays around
                // to fill quickly?
                for _ in 0..fill_len {
                    self.write_u8(0)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_encode() -> EncodeResult<()> {
        let mut buf = vec![0, 1, 2, 3, 4, 5];
        let mut enc = Encoder::new(&mut buf);
        enc.offset = 4;
        // write already reserved space
        enc.write_slice(&[5, 6])?;
        assert_eq!(enc.buffer, &mut vec![0, 1, 2, 3, 5, 6]);
        assert_eq!(enc.offset, 6);
        // reserve extra space
        enc.write_slice(&[7, 8])?;
        assert_eq!(enc.buffer, &mut vec![0, 1, 2, 3, 5, 6, 7, 8]);
        assert_eq!(enc.offset, 8);

        // start w/ empty buf
        let mut buf = vec![];
        let mut enc = Encoder::new(&mut buf);
        // reserve space & write
        enc.write_slice(&[0, 1, 2, 3])?;
        assert_eq!(enc.buffer, &mut vec![0, 1, 2, 3]);
        assert_eq!(enc.offset, 4);
        Ok(())
    }
}
