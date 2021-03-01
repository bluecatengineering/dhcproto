//use std::net::Ipv4Addr;

use std::{
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
};

use decoder::{Decodable, Decoder};

mod decoder;

/// https://tools.ietf.org/html/rfc2131#section-2
struct Message {
    /// op code / message type
    opcode: Opcode,
    /// Hardware address type: https://tools.ietf.org/html/rfc3232
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16, // todo: enum
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 6],
    sname: String,
    file: String,
    // TODO options
}

enum Opcode {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl<'r> Decodable<'r> for Message {
    fn read(decoder: &mut Decoder<'r>) -> io::Result<Self> {
        todo!()
    }
}
