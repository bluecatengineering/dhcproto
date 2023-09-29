# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.10.0]

### Fixed

- dhcpv6: Fix OPTION_STATUS_CODE parsing. After a status code option, all following options will be corrupted

### Added

- add v4 options 21/24/25/34 & 62..65 & 68..77
- add v4 opts 88 & 89. 88 uses same domain long opt encoding as 119

### Changed

- Picked more consistent name & casing for option types
- remove Domain type and just re-export trust-dns Name

## [0.9.0]

### Added

- `PartialOrd`/`Ord` impls for `v4::DhcpOption`/`v6::DhcpOption`/`v4::OptionCode`/`v6::OptionCode`
- `v6::DhcpOptions` methods `*_all`
- `v6::Duid` & methods
- `v6::Message` `Display` impl
- `v6::RelayMessage`
- `v4::NISServerAddr` added to options
- `v4::Message::clear_sname`/`clear_fname` added
- dhcpv4 opt client fqdn added. uses trust-dns-proto's `Name` type to decode the domain

### Changed

- internally, v6 DhcpOptions are now kept sorted by OptionCode (may become `HashMap<_, Vec<_>>` in future)
- `DhcpOptions::RelayMsg()` type changed to `RelayMessage`
- moved Duid to duid module
- added oro_codes

### Fixed

- relay agent info will be added before END opt if present [see here](https://datatracker.ietf.org/doc/html/rfc3046#section-2.1)
- fixed panic on .get for v6 options

## [0.8.0]

### Changed

- dhcpv4 option variants added (breaking)
- dhcpv4 message type variants added (breaking)
- ClientNetworkInterface removed inner tuple
- Change `has_msg_type` return type to just `bool`

### Fixed

- v6 `set_xid_num` was taking bytes from the wrong end
- dhcpv6 DomainSearchList (opt 24)

### Added

- dhcpv4 opt 119 DomainSearch
- dhcpv4 opt 114 CaptivePortal
- dhcpv4 message variants 9-18 added, breaking change for `MessageType`
- dhcpv4 added DhcpOption for 91/92/93/94/97
- UnknownOption encode/decode
- dhcpv4 options 151-157 from bulkleasequery RFC
- add `Display` impl for `v4::Message`

## [0.7.0]

### Added

- **breaking** DHCP Inform message variant

### Changed

- bug in `set_chaddr` where `hlen` was not set

## [0.6.0]

### Added

- methods for `dhcpv6::UnknownOption` & `RelayMsg`

### Changed

- exposed some dhcpv6 opt fields as `pub`
- `InterfaceId` type changed from `String` to `Vec<u8>`
- `VendorClass`/`UserClass` changed to `Vec<Vec<u8>>`

### Removed

- `ElapsedTime` and `Preference`

## [0.5.0]

### Added

- added `clear`/`is_empty`/`retain` to v4 opts & relay agent sub-opts

### Fixed

- **breaking** options enum for `v4::DhcpOption` was decoding into the wrong variants for a few types

## [0.4.1]

### Added

- expose methods so one can actually create RelayInfo/RelayAgentInformation
- methods to get the data out of various Unknown variants for opts/relay
- added option 118 subnet selection
- return impl Iterator for relay/opt iterator methods
- more docs for opts/relay info

### Changed

- `DhcpOption` variants added for v4
- some opt method return types have changed `iter()`/`iter_mut()`

## [0.3.0]

### Added

### Changed

- `sname`/`fname` types changed from `String` to `[u8]`
- perf improved for `Decoder`
