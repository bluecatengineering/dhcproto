use alloc::borrow::Cow;
use core::{fmt::Debug, net::Ipv4Addr};

use crate::{
    Decoder,
    error::DecodeError,
    v4::{DecodeResult, Flags, HType, Opcode, OptionCode},
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

    /// opcode
    pub fn opcode(&self) -> Opcode {
        self.buffer[0].into()
    }

    /// hardware type
    pub fn htype(&self) -> HType {
        self.buffer[1].into()
    }

    /// hardware len
    pub fn hlen(&self) -> u8 {
        self.buffer[2]
    }

    /// hops
    pub fn hops(&self) -> u8 {
        self.buffer[3]
    }

    /// transaction id
    pub fn xid(&self) -> u32 {
        u32::from_be_bytes(self.buffer[4..=7].try_into().unwrap())
    }

    /// seconds elapsed since client began address acquisition or renewal
    pub fn secs(&self) -> u16 {
        u16::from_be_bytes(self.buffer[8..=9].try_into().unwrap())
    }

    pub fn flags(&self) -> Flags {
        u16::from_be_bytes(self.buffer[10..=11].try_into().unwrap()).into()
    }

    /// client addr (siaddr)
    pub fn ciaddr(&self) -> Ipv4Addr {
        TryInto::<[u8; 4]>::try_into(&self.buffer[12..=15])
            .unwrap()
            .into()
    }

    /// your addr (siaddr)
    pub fn yiaddr(&self) -> Ipv4Addr {
        TryInto::<[u8; 4]>::try_into(&self.buffer[16..=19])
            .unwrap()
            .into()
    }

    /// server addr (siaddr)
    pub fn siaddr(&self) -> Ipv4Addr {
        TryInto::<[u8; 4]>::try_into(&self.buffer[20..=23])
            .unwrap()
            .into()
    }

    /// gateway addr (giaddr)
    pub fn giaddr(&self) -> Ipv4Addr {
        TryInto::<[u8; 4]>::try_into(&self.buffer[24..=27])
            .unwrap()
            .into()
    }

    /// chaddr
    pub fn chaddr(&self) -> &'a [u8] {
        &self.buffer[28..28 + self.hlen() as usize]
    }

    // For variable-length fields, we can return slices
    // The sname and file fields are null-terminated strings

    /// server name
    pub fn sname(&self) -> &'a [u8] {
        debug_assert!(
            self.buffer.get(44..108).is_some(),
            "not enough bytes for sname"
        );
        let sname_bytes = &self.buffer[44..108];
        let end = sname_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sname_bytes.len());
        &sname_bytes[..end]
    }

    /// file name
    pub fn fname(&self) -> &'a [u8] {
        debug_assert!(
            self.buffer.get(108..236).is_some(),
            "not enough bytes for fname"
        );
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
        if self.buffer[236..240] != crate::v4::MAGIC {
            return DhcpOptionIterator::empty();
        }
        DhcpOptionIterator::new(&self.buffer[240..])
    }
}

/// An iterator over DHCP options. Handles long-form encoding
#[derive(Debug)]
pub struct DhcpOptionIterator<'a> {
    decoder: Decoder<'a>,
}

/// Represents a single DHCP option, which may be concatenated from multiple parts.
#[derive(Debug)]
pub struct DhcpOption<'a> {
    code: OptionCode,
    data: Cow<'a, [u8]>,
}

impl DhcpOption<'_> {
    /// option code
    pub fn code(&self) -> OptionCode {
        self.code
    }

    /// data len
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// option data
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Consumes the raw option and attempts to parse it into owned `DhcpOption`.
    /// This method will do allocations
    pub fn into_option(self) -> DecodeResult<crate::v4::options::DhcpOption> {
        let mut decoder = Decoder::new(&self.data);
        crate::v4::decode_inner(self.code(), self.len(), &mut decoder)
    }
}

impl<'a> DhcpOptionIterator<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            decoder: Decoder::new(buffer),
        }
    }

    pub fn empty() -> DhcpOptionIterator<'a> {
        Self {
            decoder: Decoder::new(&[]),
        }
    }
}

impl<'a> Iterator for DhcpOptionIterator<'a> {
    type Item = DhcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let code = self.decoder.read_u8().ok()?;

            match code {
                0 => continue,      // Pad
                255 => return None, // End
                _ => {
                    let len = self.decoder.read_u8().ok()?;
                    let data = self.decoder.read_slice(len as usize).ok()?;

                    let mut buf = Cow::Borrowed(data);

                    let mut lookahead = self.decoder;
                    let mut bytes_consumed = 0;

                    while let Ok(next_code) = lookahead.peek_u8() {
                        if next_code == code {
                            // Advance past the code we just peeked
                            lookahead.read_u8().ok()?;

                            let next_len = lookahead.read_u8().ok()?;
                            let next_data = lookahead.read_slice(next_len as usize).ok()?;

                            buf.to_mut().extend_from_slice(next_data);
                            bytes_consumed += 1 + 1 + next_len as usize;
                        } else {
                            break;
                        }
                    }

                    if bytes_consumed > 0 {
                        self.decoder.read_slice(bytes_consumed).unwrap();
                    }

                    return Some(DhcpOption {
                        code: OptionCode::from(code),
                        data: buf,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    fn bootreq() -> Vec<u8> {
        vec![
            1u8, // op
            2,   // htype
            3,   // hlen
            4,   // ops
            5, 6, 7, 8, // xid
            9, 10, // secs
            11, 12, // flags
            13, 14, 15, 16, // ciaddr
            17, 18, 19, 20, // yiaddr
            21, 22, 23, 24, // siaddr
            25, 26, 27, 28, // giaddr
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, // chaddr
            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
            67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
            89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            0, // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 0, 0, 0, 0, 0, 0, 0,
            0, // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",
            99, 130, 83, 99, // magic cookie
        ]
    }

    #[test]
    fn test_bootreq() {
        let buf = bootreq();
        let msg = Message::new(&buf).unwrap();
        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.htype(), HType::ExperimentalEth);
        assert_eq!(msg.hlen(), 3);
        assert_eq!(msg.hops(), 4);
        assert_eq!(msg.xid(), 0x05060708);
        assert_eq!(msg.secs(), 0x090A);
        assert_eq!(u16::from(msg.flags()), 0x0B0C);
        assert_eq!(msg.ciaddr(), Ipv4Addr::new(13, 14, 15, 16));
        assert_eq!(msg.yiaddr(), Ipv4Addr::new(17, 18, 19, 20));
        assert_eq!(msg.siaddr(), Ipv4Addr::new(21, 22, 23, 24));
        assert_eq!(msg.giaddr(), Ipv4Addr::new(25, 26, 27, 28));
        assert_eq!(msg.chaddr(), &[29, 30, 31]);
        assert_eq!(
            msg.sname(),
            &[
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
                87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
                106, 107
            ]
        );
        assert_eq!(
            msg.fname(),
            &[
                109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
                125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
                124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
                123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
                121, 122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
                120, 121, 122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
                119, 120, 121, 122, 123, 124, 125, 109
            ]
        );
        assert!(msg.opts().next().is_none());
    }

    #[test]
    fn test_empty() {
        // Empty buffer
        let buffer = [];
        let mut iter = DhcpOptionIterator::new(&buffer);
        assert!(iter.next().is_none());

        // Just the end option
        let buffer = [255];
        let mut iter = DhcpOptionIterator::new(&buffer);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_pad() {
        // Padding before an option and end
        let buffer = [0, 0, 53, 1, 1, 0, 255];
        let mut iter = DhcpOptionIterator::new(&buffer);

        let option = iter.next().unwrap();
        assert_eq!(option.code, OptionCode::MessageType);
        assert_eq!(option.data, Cow::from(&[1][..]));

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_simple_options() {
        let buffer = [
            53, 1, 1, // DHCP Message Type: Discover (1)
            61, 7, 1, 11, 22, 33, 44, 55, 66, // Client Identifier
            55, 2, 1, 3,   // Parameter Request List: Subnet Mask (1), Router (3)
            255, // End
        ];
        let mut iter = DhcpOptionIterator::new(&buffer);

        let opt1 = iter.next().unwrap();
        assert_eq!(opt1.code, OptionCode::MessageType);
        assert_eq!(opt1.data, Cow::from(&[1][..]));

        let opt2 = iter.next().unwrap();
        assert_eq!(opt2.code, OptionCode::ClientIdentifier);
        assert_eq!(opt2.data, Cow::from(&[1, 11, 22, 33, 44, 55, 66][..]));

        let opt3 = iter.next().unwrap();
        assert_eq!(opt3.code, OptionCode::ParameterRequestList);
        assert_eq!(opt3.data, Cow::from(&[1, 3][..]));

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_concatenated_option() {
        let buffer = [
            12, 5, b'h', b'e', b'l', b'l', b'o', // Host Name part 1
            12, 6, b' ', b'w', b'o', b'r', b'l', b'd', // Host Name part 2
            255,
        ];
        let mut iter = DhcpOptionIterator::new(&buffer);

        let option = iter.next().unwrap();
        assert_eq!(option.code, OptionCode::Hostname);

        // Check that the data is concatenated and is now owned
        let expected_data = b"hello world";
        assert_eq!(option.data, Cow::from(&expected_data[..]));
        assert!(matches!(option.data, Cow::Owned(_)));

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_mixed_simple_and_concatenated() {
        let buffer = [
            53, 1, 1, // Simple option
            50, 4, 192, 168, 1, 100, // Another simple option
            43, 3, b'd', b'e', b'f', // Concatenated option part 1
            43, 3, b'g', b'h', b'i', // Concatenated option part 2
            54, 4, 192, 168, 1, 1, // A final simple option
            255,
        ];
        let mut iter = DhcpOptionIterator::new(&buffer);

        let opt1 = iter.next().unwrap();
        assert_eq!(opt1.code, OptionCode::MessageType);
        assert_eq!(opt1.data, Cow::from(&[1][..]));

        let opt3 = iter.next().unwrap();
        assert_eq!(opt3.code, OptionCode::RequestedIpAddress);
        assert_eq!(opt3.data, Cow::from(&[192, 168, 1, 100][..]));

        let opt2 = iter.next().unwrap();
        assert_eq!(opt2.code, OptionCode::VendorExtensions);
        assert_eq!(opt2.data, Cow::from(&b"defghi"[..]));
        assert!(matches!(opt2.data, Cow::Owned(_)));

        let opt4 = iter.next().unwrap();
        assert_eq!(opt4.code, OptionCode::ServerIdentifier);
        assert_eq!(opt4.data, Cow::from(&[192, 168, 1, 1][..]));

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_malformed_length() {
        // Length of 10 but only 3 bytes remaining
        let buffer = [1, 10, 1, 2, 3];
        let mut iter = DhcpOptionIterator::new(&buffer);
        // The parser should detect this and stop, returning None.
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_malformed_abrupt_end() {
        // Buffer ends right after an option code
        let buffer = [53];
        let mut iter = DhcpOptionIterator::new(&buffer);
        assert!(iter.next().is_none());

        // Buffer ends after a length field
        let buffer = [53, 5];
        let mut iter = DhcpOptionIterator::new(&buffer);
        assert!(iter.next().is_none());
    }
}
