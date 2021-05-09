use crate::error::{DecodeError, DecodeResult};

use std::{convert::TryInto, mem};

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &'_ mut Decoder<'r>) -> DecodeResult<Self>;

    // Returns the object in binary form
    //fn from_bytes(bytes: &'r [u8]) -> io::Result<Self> {
    //    let mut decoder = Decoder::new(bytes);
    //    Self::read(&mut decoder)
    //}
}

#[derive(Debug)]
pub struct Decoder<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Decoder { buffer, index: 0 }
    }

    /// read a u8
    pub fn read_u8(&mut self) -> DecodeResult<u8> {
        Ok(self.read::<u8>()?[0])
    }

    /// read a u32
    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(self.read::<u32>()?.try_into()?))
    }

    /// read a i32
    pub fn read_i32(&mut self) -> DecodeResult<i32> {
        Ok(i32::from_be_bytes(self.read::<i32>()?.try_into()?))
    }

    /// read a u16
    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(self.read::<u16>()?.try_into()?))
    }

    fn read<T>(&mut self) -> DecodeResult<&'a [u8]> {
        let len = mem::size_of::<T>();
        let end = self
            .index
            .checked_add(len)
            .ok_or(DecodeError::AddOverflow)?;
        let bytes = self
            .buffer
            .get(self.index..end)
            .ok_or(DecodeError::EndOfBuffer { index: end })?;
        self.index = end;
        Ok(bytes)
    }

    /// read a constant number of bytes
    pub fn read_bytes<const N: usize>(&mut self) -> DecodeResult<&'a [u8]> {
        let end = self.index.checked_add(N).ok_or(DecodeError::AddOverflow)?;
        let bytes = self
            .buffer
            .get(self.index..end)
            .ok_or(DecodeError::EndOfBuffer { index: end })?;
        self.index = end;
        Ok(bytes)
    }

    /// read a slice of bytes determined at runtime
    pub fn read_slice(&mut self, len: usize) -> DecodeResult<&'a [u8]> {
        let end = self
            .index
            .checked_add(len)
            .ok_or(DecodeError::AddOverflow)?;
        let slice = self
            .buffer
            .get(self.index..end)
            .ok_or(DecodeError::EndOfBuffer { index: end })?;
        self.index = end;
        Ok(slice)
    }
}
