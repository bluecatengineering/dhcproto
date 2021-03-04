use std::io::{self, Error, ErrorKind};
use std::{convert::TryInto, mem};

use crate::error::*;

// TODO:
// - add error type (not io::Error)

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self>;

    // Returns the object in binary form
    //fn from_bytes(bytes: &'r [u8]) -> io::Result<Self> {
    //    let mut decoder = Decoder::new(bytes);
    //    Self::read(&mut decoder)
    //}
}

pub struct Decoder<'a> {
    buffer: &'a [u8],
    index: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Decoder { buffer, index: 0 }
    }

    /// Pop one byte from the buffer
    pub fn pop(&mut self) -> DecodeResult<u8> {
        if self.index < self.buffer.len() {
            let byte = self.buffer[self.index];
            self.index += 1;
            Ok(byte)
        } else {
            Err("unexpected end of input reached".into())
        }
    }

    /// Reads a byte from the buffer, equivalent to `Self::pop()`
    //pub fn read_u8(&mut self) -> DecodeResult<u8> {
    //    self.pop()
    //}

    pub fn read_u8(&mut self) -> DecodeResult<u8> {
        Ok(self.read::<u8>()?[0])
    }

    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(self.read::<u16>()?.try_into()?))
    }

    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(self.read::<u32>()?.try_into()?))
    }

    fn read<T>(&mut self) -> DecodeResult<&'a [u8]> {
        let len = mem::size_of::<T>();
        let end = self
            .index
            .checked_add(len)
            .ok_or(DecodeError::EndOfBuffer { index: self.index })?;

        let bytes = self
            .buffer
            .get(self.index..end)
            .ok_or(DecodeError::EndOfBuffer { index: end })?;
        // self.index += len;
        self.index = end;
        Ok(bytes)
    }
}
