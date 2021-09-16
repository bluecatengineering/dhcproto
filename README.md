# dhcproto

A DHCP parser and encoder for DHCPv4/DHCPv6. `dhcproto` aims to be a functionally complete DHCP implementation. Many common option types are implemented, PRs are welcome to flesh out missing types.

## crates.io

https://crates.io/crates/dhcproto

## Minimum Rust Version

This crate uses const generics, Rust 1.53 is required

## RFCs

DHCPv6:

- https://datatracker.ietf.org/doc/html/rfc8415
- https://datatracker.ietf.org/doc/html/rfc3646
- https://datatracker.ietf.org/doc/html/rfc3633

DHCPv4:

- https://tools.ietf.org/html/rfc2131
- https://tools.ietf.org/html/rfc3232
