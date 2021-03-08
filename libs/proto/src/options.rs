use std::collections::HashMap;

use crate::decoder::{Decodable, Decoder};
use crate::error::*;

pub struct DhcpOptions {
    options: HashMap<u8, DhcpOption>,
}

impl<'r> Decodable<'r> for DhcpOptions {
    fn read(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        let mut options: HashMap<u8, DhcpOption> = HashMap::new();

        // Read the magic cookie
        // Todo validate cookie
        let cookie = decoder.read_slice(4);
        dbg!(cookie);

        Ok(DhcpOptions { options })
    }
}

pub enum OptionCode {
    /// [RFC 2132, Pad Option](https://tools.ietf.org/html/rfc2132#section-3.1)
    Pad,

    /// [RFC 2132, End Option](https://tools.ietf.org/html/rfc2132#section-3.2)
    End,

    Unknown(u8),
}

impl From<u8> for OptionCode {
    fn from(value: u8) -> Self {
        match value {
            0 => OptionCode::Pad,
            255 => OptionCode::End,
            _ => OptionCode::Unknown(value),
        }
    }
}

enum DhcpOption {
    MessageType(MessageType),
}
#[derive(Debug)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Pack,
    Nak,
    Release,
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(mtype: u8) -> Self {
        match mtype {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Pack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            _ => MessageType::Unknown(mtype),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::message;

    use super::*;
    use anyhow::Result;

    #[test]
    fn message_type() -> Result<()> {
        let a: MessageType = 0x1u8.into();
        dbg!(a);
        Ok(())
    }
}
