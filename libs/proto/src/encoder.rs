use crate::error::{EncodeError, EncodeResult};

/// A trait for types which are deserializable to DHCP binary formats
pub trait Encodable<'a> {
    /// Read the type from the stream
    fn write(&self, enc: &'_ mut Encoder<'a>) -> EncodeResult<usize>;
}

#[derive(Debug)]
pub struct Encoder<'a> {
    buffer: &'a mut Vec<u8>,
    offset: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer, offset: 0 }
    }

    /// write bytes to buffer
    /// Return:
    ///     number of bytes written
    pub fn write_slice(&mut self, bytes: &[u8]) -> EncodeResult<usize> {
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
        Ok(additional)
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
