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
