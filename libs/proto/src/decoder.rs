use std::io::{self, Error, ErrorKind};

// TODO:
// - add error type (not io::Error)

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &mut Decoder<'r>) -> io::Result<Self>;

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
}
