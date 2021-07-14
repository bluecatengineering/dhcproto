use crate::error::{EncodeError, EncodeResult};

/// A trait for types which are deserializable to DHCP binary formats
pub trait Encodable<'a> {
    /// Read the type from the stream
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<usize>;
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

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
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

    pub fn write<const N: usize>(&mut self, bytes: [u8; N]) -> EncodeResult<usize> {
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
        Ok(additional)
    }

    pub fn write_u8(&mut self, data: u8) -> EncodeResult<usize> {
        self.write(data.to_be_bytes())
    }
    pub fn write_u16(&mut self, data: u16) -> EncodeResult<usize> {
        self.write(data.to_be_bytes())
    }
    pub fn write_u32(&mut self, data: u32) -> EncodeResult<usize> {
        self.write(data.to_be_bytes())
    }
    pub fn write_i32(&mut self, data: i32) -> EncodeResult<usize> {
        self.write(data.to_be_bytes())
    }
    /// Writes bytes to buffer and pads with 0 bytes up to some fill_len
    ///
    /// Returns
    ///    Err - if bytes.len() is greater then fill_len
    pub fn write_fill_bytes(&mut self, bytes: &[u8], fill_len: usize) -> EncodeResult<usize> {
        if bytes.len() > fill_len {
            return Err(EncodeError::StringSizeTooBig { len: bytes.len() });
        }
        let nul_len = fill_len - bytes.len();
        let mut len = 0;
        len += self.write_slice(bytes)?;
        for _ in 0..nul_len {
            len += self.write_u8(0)?;
        }
        Ok(len)
    }
    /// Writes string to buffer and pads with 0 bytes up to some fill_len
    /// if String is None then write fill_len 0 bytes
    ///
    /// Returns
    ///    Err - if bytes.len() is greater then fill_len
    pub fn write_fill_string(
        &mut self,
        s: &Option<String>,
        fill_len: usize,
    ) -> EncodeResult<usize> {
        let mut len = 0;
        match s {
            Some(sname) => {
                let bytes = sname.as_bytes();
                len += self.write_fill_bytes(bytes, fill_len)?;
            }
            None => {
                // should we keep some static [0;64] arrays around
                // to fill quickly?
                for _ in 0..fill_len {
                    len += self.write_u8(0)?;
                }
            }
        }
        Ok(len)
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
