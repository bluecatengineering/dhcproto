use std::net::Ipv4Addr;

enum Opcode {
    bootRequest,
    bootReply,
}

/// https://tools.ietf.org/html/rfc2131#section-2
struct Message {
    /// op code / message type
    opcode: Opcode,
    /// Hardware address type.
    /// https://tools.ietf.org/html/rfc3232
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
}
