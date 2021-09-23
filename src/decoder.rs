//! Decodable trait & Decoder
use crate::error::{DecodeError, DecodeResult};

use std::{
    array::TryFromSliceError,
    convert::TryInto,
    ffi::{CStr, CString},
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable: Sized {
    /// Read the type from the stream
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self>;

    /// Returns the object in binary form
    fn from_bytes(bytes: &[u8]) -> DecodeResult<Self> {
        let mut decoder = Decoder::new(bytes);
        Self::decode(&mut decoder)
    }
}

/// Decoder type. Wraps a buffer which only contains bytes that have not been read yet
#[derive(Debug)]
pub struct Decoder<'a> {
    buffer: &'a [u8],
}

impl<'a> Decoder<'a> {
    /// Create a new Decoder
    pub fn new(buffer: &'a [u8]) -> Self {
        Decoder { buffer }
    }

    /// read a u8
    pub fn read_u8(&mut self) -> DecodeResult<u8> {
        Ok(u8::from_be_bytes(self.read::<{ mem::size_of::<u8>() }>()?))
    }

    /// read a u32
    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(
            self.read::<{ mem::size_of::<u32>() }>()?,
        ))
    }

    /// read a i32
    pub fn read_i32(&mut self) -> DecodeResult<i32> {
        Ok(i32::from_be_bytes(
            self.read::<{ mem::size_of::<i32>() }>()?,
        ))
    }

    /// read a u16
    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(
            self.read::<{ mem::size_of::<u16>() }>()?,
        ))
    }

    /// read a u64
    pub fn read_u64(&mut self) -> DecodeResult<u64> {
        Ok(u64::from_be_bytes(
            self.read::<{ mem::size_of::<u64>() }>()?,
        ))
    }

    /// read a `N` bytes into slice
    pub fn read<const N: usize>(&mut self) -> DecodeResult<[u8; N]> {
        if N > self.buffer.len() {
            return Err(DecodeError::NotEnoughBytes);
        }
        let (slice, remaining) = self.buffer.split_at(N);
        self.buffer = remaining;
        // can't panic-- condition checked above
        Ok(slice.try_into().unwrap())
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

    pub fn read_nul_bytes<const MAX: usize>(&mut self) -> DecodeResult<Option<Vec<u8>>> {
        let bytes = self.read::<MAX>()?;
        let nul_idx = bytes.iter().position(|&b| b == 0);
        match nul_idx {
            Some(n) if n == 0 => Ok(None),
            Some(n) => Ok(Some(bytes[..=n].to_vec())),
            // TODO: error?
            None => Ok(None),
        }
    }

    /// read `MAX` length bytes and read into utf-8 encoded `String`
    pub fn read_nul_string<const MAX: usize>(&mut self) -> DecodeResult<Option<String>> {
        Ok(self
            .read_nul_bytes::<MAX>()?
            .map(|ref bytes| str::from_utf8(bytes).map(|s| s.to_owned()))
            .transpose()?)
    }

    /// read a slice of bytes determined at runtime
    pub fn read_slice(&mut self, len: usize) -> DecodeResult<&'a [u8]> {
        if len > self.buffer.len() {
            return Err(DecodeError::NotEnoughBytes);
        }
        let (slice, remaining) = self.buffer.split_at(len);
        self.buffer = remaining;
        Ok(slice)
    }

    /// Read a utf-8 encoded String
    pub fn read_string(&mut self, len: usize) -> DecodeResult<String> {
        let slice = self.read_slice(len)?;
        Ok(str::from_utf8(slice)?.to_owned())
    }

    /// Read an ipv4 addr
    pub fn read_ipv4(&mut self, length: usize) -> DecodeResult<Ipv4Addr> {
        if length != 4 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let bytes = self.read::<4>()?;
        Ok(bytes.into())
    }

    /// Read a list of ipv4 addrs
    pub fn read_ipv4s(&mut self, length: usize) -> DecodeResult<Vec<Ipv4Addr>> {
        // must be multiple of 4
        if length % 4 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ips = self.read_slice(length as usize)?;
        Ok(ips
            .chunks(4)
            .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]].into())
            .collect())
    }

    /// Read a list of ipv6 addrs
    pub fn read_ipv6s(&mut self, length: usize) -> DecodeResult<Vec<Ipv6Addr>> {
        // must be multiple of 16
        if length % 16 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ips = self.read_slice(length as usize)?;
        // type annotations needed below
        Ok(ips
            .chunks(16)
            .map(|bytes| Ok::<_, TryFromSliceError>(TryInto::<[u8; 16]>::try_into(bytes)?.into()))
            .collect::<Result<Vec<Ipv6Addr>, _>>()?)
    }

    /// Read a list of ipv4 pairs
    pub fn read_pair_ipv4s(&mut self, length: usize) -> DecodeResult<Vec<(Ipv4Addr, Ipv4Addr)>> {
        // must be multiple of 8
        if length % 8 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
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

    /// Read a bool
    pub fn read_bool(&mut self) -> DecodeResult<bool> {
        Ok(self.read_u8()? == 1)
    }

    /// return slice of buffer start at index of unread data
    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }
}
