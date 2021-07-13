use crate::error::{DecodeError, DecodeResult};

use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    mem,
    net::Ipv4Addr,
    str,
};

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable<'r>: Sized {
    /// Read the type from the stream
    fn read(decoder: &'_ mut Decoder<'r>) -> DecodeResult<Self>;

    // Returns the object in binary form
    fn from_bytes(bytes: &'r [u8]) -> DecodeResult<Self> {
        let mut decoder = Decoder::new(bytes);
        Self::read(&mut decoder)
    }
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
        Ok(self.read::<{ mem::size_of::<u8>() }>()?[0])
    }

    /// read a u32
    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(
            self.read::<{ mem::size_of::<u32>() }>()?.try_into()?,
        ))
    }

    /// read a i32
    pub fn read_i32(&mut self) -> DecodeResult<i32> {
        Ok(i32::from_be_bytes(
            self.read::<{ mem::size_of::<i32>() }>()?.try_into()?,
        ))
    }

    /// read a u16
    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(
            self.read::<{ mem::size_of::<u16>() }>()?.try_into()?,
        ))
    }

    /// read a `N` bytes into slice
    pub fn read<const N: usize>(&mut self) -> DecodeResult<&'a [u8]> {
        let end = self.index.checked_add(N).ok_or(DecodeError::AddOverflow)?;
        let bytes = self
            .buffer
            .get(self.index..end)
            .ok_or(DecodeError::EndOfBuffer { index: end })?;
        self.index = end;
        Ok(bytes)
    }

    /// read a `MAX` length bytes into nul terminated `CString`
    pub fn read_cstring<const MAX: usize>(&mut self) -> DecodeResult<Option<CString>> {
        let bytes = self.read::<MAX>()?;
        let nul_idx = bytes.iter().position(|&b| b == 0);
        match nul_idx {
            Some(n) if n == 0 => Ok(None),
            Some(n) => Ok(Some(CStr::from_bytes_with_nul(&bytes[..=n])?.to_owned())),
            // TODO: error?
            None => Ok(None),
        }
    }

    /// read `MAX` length bytes and read into utf-8 encoded `String`
    pub fn read_const_string<const MAX: usize>(&mut self) -> DecodeResult<Option<String>> {
        let bytes = self.read::<MAX>()?;
        let nul_idx = bytes.iter().position(|&b| b == 0);
        match nul_idx {
            Some(n) if n == 0 => Ok(None),
            Some(n) => Ok(Some(str::from_utf8(&bytes[..=n])?.to_owned())),
            // TODO: error?
            None => Ok(None),
        }
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

    pub fn read_string(&mut self, len: usize) -> DecodeResult<String> {
        let slice = self.read_slice(len)?;
        Ok(str::from_utf8(slice)?.to_owned())
    }

    pub fn read_ip(&mut self, length: usize) -> DecodeResult<Ipv4Addr> {
        let bytes = self.read_slice(length as usize)?;
        Ok([bytes[0], bytes[1], bytes[2], bytes[3]].into())
    }

    pub fn read_ips(&mut self, length: usize) -> DecodeResult<Vec<Ipv4Addr>> {
        let ips = self.read_slice(length as usize)?;
        Ok(ips
            .chunks(4)
            .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]].into())
            .collect())
    }

    pub fn read_pair_ips(&mut self, length: usize) -> DecodeResult<Vec<(Ipv4Addr, Ipv4Addr)>> {
        let ips = self.read_slice(length as usize)?;
        Ok(ips
            .chunks(8)
            .map(|bytes| {
                (
                    [bytes[0], bytes[1], bytes[2], bytes[3]].into(),
                    [bytes[4], bytes[5], bytes[6], bytes[7]].into(),
                )
            })
            .collect())
    }
}
