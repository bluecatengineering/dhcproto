use std::io::{self, Error, ErrorKind};

use crate::error::*;

// TODO:
// - add error type (not io::Error)

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &mut Decoder<'r>) -> ProtoResult<Self>;

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
    pub fn pop(&mut self) -> ProtoResult<u8> {
        if self.index < self.buffer.len() {
            let byte = self.buffer[self.index];
            self.index += 1;
            Ok(byte)
        } else {
            Err("unexpected end of input reached".into())
        }
    }

    /// Reads a byte from the buffer, equivalent to `Self::pop()`
    pub fn read_u8(&mut self) -> ProtoResult<u8> {
        self.pop()
    }
}
