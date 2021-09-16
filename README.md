# dhcproto

A DHCP parser and encoder for DHCPv4/DHCPv6. `dhcproto` aims to be a functionally complete DHCP implementation. Many common option types are implemented, PRs are welcome to flesh out missing types.

## crates.io

https://crates.io/crates/dhcproto

## Minimum Rust Version

This crate uses const generics, Rust 1.53 is required

## Examples

### (v4) Decoding/Encoding

```rust
use dhcproto::v4::{Message, Encoder, Decoder, Decodable, Encodable};
// decode
let bytes = dhcp_offer();
let msg = Message::decode(&mut Decoder::new(&bytes))?;
// now encode
let mut buf = Vec::new();
let mut e = Encoder::new(&mut buf);
msg.encode(&mut e)?;
```

### (v4) Constructing messages

```rust
use dhcproto::{v4, Encodable, Encoder};
// hardware addr
let chaddr = vec![
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
];
// construct a new Message
let mut msg = v4::Message::default();
msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
    .set_chaddr(&chaddr) // set chaddr
    .opts_mut()
    .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type

// set some more options
msg.opts_mut()
    .insert(v4::DhcpOption::ParameterRequestList(vec![
        v4::OptionCode::SubnetMask,
        v4::OptionCode::Router,
        v4::OptionCode::DomainNameServer,
        v4::OptionCode::DomainName,
    ]));
msg.opts_mut()
    .insert(v4::DhcpOption::ClientIdentifier(chaddr));

// now encode to bytes
let mut buf = Vec::new();
let mut e = Encoder::new(&mut buf);
msg.encode(&mut e)?;
// buf now has the contents of the encoded DHCP message
```

## RFCs

DHCPv6:

- https://datatracker.ietf.org/doc/html/rfc8415
- https://datatracker.ietf.org/doc/html/rfc3646
- https://datatracker.ietf.org/doc/html/rfc3633

DHCPv4:

- https://tools.ietf.org/html/rfc2131
- https://tools.ietf.org/html/rfc3232
