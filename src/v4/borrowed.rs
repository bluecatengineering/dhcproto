use alloc::borrow::Cow;
use core::{fmt::Debug, net::Ipv4Addr};

use crate::{
    error::DecodeError,
    v4::{Flags, HType, Opcode, OptionCode},
};

/// A lazily decoded DHCPv4 message.
/// It holds a reference to the original byte buffer and provides
/// methods to access fields. Most fields are parsed on-demand.
#[derive(Debug)]
pub struct Message<'a> {
    buffer: &'a [u8],
}

impl<'a> Message<'a> {
    /// Creates a new `Message` from a byte slice.
    /// This is a zero-copy operation and does not perform any allocations.
    pub fn new(buffer: &'a [u8]) -> Result<Self, DecodeError> {
        if buffer.len() < 240 {
            return Err(DecodeError::NotEnoughBytes);
        }
        Ok(Self { buffer })
    }

    // Accessor methods for fixed-size fields. These would read directly from the buffer.

    pub fn opcode(&self) -> Opcode {
        self.buffer[0].into()
    }

    pub fn htype(&self) -> HType {
        self.buffer[1].into()
    }

    pub fn hlen(&self) -> u8 {
        self.buffer[2]
    }

    pub fn hops(&self) -> u8 {
        self.buffer[3]
    }

    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
    }

    pub fn secs(&self) -> u16 {
        u16::from_be_bytes(self.buffer[8..10].try_into().unwrap())
    }

    pub fn flags(&self) -> Flags {
        u16::from_be_bytes(self.buffer[10..12].try_into().unwrap()).into()
    }

    pub fn ciaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        )
    }

    pub fn yiaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        )
    }

    pub fn siaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[20],
            self.buffer[21],
            self.buffer[22],
            self.buffer[23],
        )
    }

    pub fn giaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[24],
            self.buffer[25],
            self.buffer[26],
            self.buffer[27],
        )
    }

    pub fn chaddr(&self) -> &'a [u8] {
        &self.buffer[28..28 + self.hlen() as usize]
    }

    // For variable-length fields, we can return slices.
    // The sname and file fields are null-terminated strings.

    pub fn sname(&self) -> &'a [u8] {
        let sname_bytes = &self.buffer[44..108];
        let end = sname_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sname_bytes.len());
        &sname_bytes[..end]
    }

    pub fn fname(&self) -> &'a [u8] {
        let file_bytes = &self.buffer[108..236];
        let end = file_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(file_bytes.len());
        &file_bytes[..end]
    }

    /// Returns a `DhcpOptions` iterator that lazily parses DHCP options.
    pub fn opts(&self) -> DhcpOptionIterator<'a> {
        // Magic cookie check
        if self.buffer[236..240] != [99, 130, 83, 99] {
            return DhcpOptionIterator::empty();
        }
        DhcpOptionIterator::new(&self.buffer[240..])
    }
}

/// An iterator over DHCP options. Handles long-form encoding
#[derive(Debug)]
pub struct DhcpOptionIterator<'a> {
    buffer: &'a [u8],
}

/// Represents a single DHCP option, which may be concatenated from multiple parts.
#[derive(Debug)]
pub struct DhcpOption<'a> {
    pub code: OptionCode,
    pub data: Cow<'a, [u8]>,
}

impl<'a> DhcpOptionIterator<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Parses a single raw option from the buffer without advancing the iterator.
    fn peek_opt(buffer: &'a [u8]) -> Option<(OptionCode, &'a [u8], &'a [u8])> {
        if buffer.is_empty() {
            return None;
        }

        let code = OptionCode::from(buffer[0]);
        match code {
            OptionCode::Pad => Some((code, &[], &buffer[1..])),
            OptionCode::End => Some((code, &[], &buffer[1..])),
            _ => {
                if buffer.len() < 2 {
                    return None; // Malformed
                }
                let len = buffer[1] as usize;
                if buffer.len() < 2 + len {
                    return None; // Malformed
                }
                let data = &buffer[2..2 + len];
                let remaining = &buffer[2 + len..];
                Some((code, data, remaining))
            }
        }
    }

    fn empty() -> DhcpOptionIterator<'a> {
        Self { buffer: &[] }
    }
}

impl<'a> Iterator for DhcpOptionIterator<'a> {
    type Item = DhcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Peek at the next raw option from our current position
            let (code, data, remaining) = Self::peek_opt(self.buffer)?;

            match code {
                // skip Pad
                OptionCode::Pad => {
                    self.buffer = remaining;
                    continue;
                }
                // end
                OptionCode::End => {
                    self.buffer = remaining;
                    return None;
                }
                _ => {
                    // This is our first segment. Start with its data as a borrowed slice.
                    let mut data: Cow<'a, [u8]> = Cow::Borrowed(data);

                    // Advance our main buffer past this first segment
                    self.buffer = remaining;

                    // Look ahead to see if subsequent options have the same code
                    let mut lookahead_buffer = remaining;
                    while let Some((next_code, next_data, next_remaining)) =
                        Self::peek_opt(lookahead_buffer)
                    {
                        if next_code == code {
                            // The next option is a continuation.
                            // We must now allocate to concatenate the data.
                            data.to_mut().extend_from_slice(next_data);

                            // Advance the main buffer and the lookahead buffer past this segment
                            self.buffer = next_remaining;
                            lookahead_buffer = next_remaining;
                        } else {
                            // Different option found, stop concatenating
                            break;
                        }
                    }

                    return Some(DhcpOption { code, data });
                }
            }
        }
    }
}
