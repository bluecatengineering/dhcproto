use core::fmt;

use hickory_proto::rr::Name;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeError, DecodeResult, EncodeResult},
};

/// DHCPv6 Client FQDN option (option 39).
///
/// <https://datatracker.ietf.org/doc/html/rfc4704#section-4>
///
/// Wire format is a flags octet followed by a domain name encoded as
/// described in RFC 8415 §10 (no DNS name compression). The domain may be:
///
/// * a fully-qualified name (terminated with a zero-length label)
/// * a partial name (one or more labels, no terminating zero)
/// * empty (`Name::new()`, flags-only) — the client is asking the server to
///   generate a name
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientFqdn {
    pub(crate) flags: FqdnFlags,
    pub(crate) domain: Name,
}

impl ClientFqdn {
    /// Create a new Client FQDN option.
    pub fn new(flags: FqdnFlags, domain: Name) -> Self {
        Self { flags, domain }
    }

    pub fn flags(&self) -> FqdnFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: FqdnFlags) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn domain(&self) -> &Name {
        &self.domain
    }

    pub fn set_domain(&mut self, domain: Name) -> &mut Self {
        self.domain = domain;
        self
    }

    pub fn domain_mut(&mut self) -> &mut Name {
        &mut self.domain
    }
}

impl Decodable for ClientFqdn {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(Self {
            flags: FqdnFlags::new(decoder.read_u8()?),
            domain: decode_domain(decoder)?,
        })
    }
}

impl Encodable for ClientFqdn {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u8(self.flags.into())?;
        encode_domain(&self.domain, e)
    }
}

/// RFC 4704 §4.1 flags. Bits: `MBZ | N | O | S`.
///
/// * `S` = 0x01 — server should perform AAAA RR updates
/// * `O` = 0x02 — server overrode the client preference
/// * `N` = 0x04 — client wants no DNS updates
///
/// There is no `E` bit and no RCODE fields (those exist only in DHCPv4 /
/// RFC 4702).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Default, Clone, PartialEq, Eq, Hash)]
pub struct FqdnFlags(u8);

impl fmt::Debug for FqdnFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FqdnFlags")
            .field("N", &self.n())
            .field("O", &self.o())
            .field("S", &self.s())
            .finish()
    }
}

impl fmt::Display for FqdnFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FqdnFlags {
    /// Create new FqdnFlags from a raw octet.
    pub fn new(n: u8) -> Self {
        Self(n)
    }

    /// Status of the N flag.
    pub fn n(&self) -> bool {
        (self.0 & 0x04) > 0
    }

    /// Set the N bit. If `true`, also forces S=0 (same policy as v4).
    pub fn set_n(mut self, bit: bool) -> Self {
        if bit {
            self.0 |= 0x04;
            self = self.set_s(false);
        } else {
            self.0 &= 0xfb;
        }
        self
    }

    pub fn set_n_mut(&mut self, bit: bool) -> &mut Self {
        *self = self.set_n(bit);
        self
    }

    /// Status of the O flag.
    pub fn o(&self) -> bool {
        (self.0 & 0x02) > 0
    }

    /// Set the O bit.
    pub fn set_o(mut self, bit: bool) -> Self {
        if bit {
            self.0 |= 0x02;
        } else {
            self.0 &= 0xfd;
        }
        self
    }

    pub fn set_o_mut(&mut self, bit: bool) -> &mut Self {
        *self = self.set_o(bit);
        self
    }

    /// Status of the S flag.
    pub fn s(&self) -> bool {
        (self.0 & 0x01) > 0
    }

    /// Set the S bit. Indicates whether the server should perform an AAAA RR update.
    pub fn set_s(mut self, bit: bool) -> Self {
        if bit {
            self.0 |= 0x01;
        } else {
            self.0 &= 0xfe;
        }
        self
    }

    pub fn set_s_mut(&mut self, bit: bool) -> &mut Self {
        *self = self.set_s(bit);
        self
    }
}

impl From<u8> for FqdnFlags {
    fn from(n: u8) -> Self {
        Self(n)
    }
}

impl From<FqdnFlags> for u8 {
    fn from(f: FqdnFlags) -> Self {
        f.0
    }
}

/// Encode a DNS name without compression.
///
/// `Name::emit` / `emit_as_canonical` always write a terminating root label,
/// which is wrong for the partial and empty names RFC 4704 allows. Write
/// labels only, and the root `0` only when `name.is_fqdn()`.
pub(crate) fn encode_domain(name: &Name, e: &mut Encoder<'_>) -> EncodeResult<()> {
    for label in name.iter() {
        e.write_u8(label.len() as u8)?;
        e.write_slice(label)?;
    }
    if name.is_fqdn() {
        e.write_u8(0)?;
    }
    Ok(())
}

/// Decode a DNS name without compression.
///
/// Stops at a root label (FQDN), or at the end of the option payload
/// (partial / empty name). Length bytes `>= 0xC0` are rejected so a
/// compression pointer is not treated as a 192-byte label.
pub(crate) fn decode_domain(decoder: &mut Decoder<'_>) -> DecodeResult<Name> {
    let mut name = Name::new();
    loop {
        match decoder.read_u8() {
            Ok(0) => {
                name.set_fqdn(true);
                break;
            }
            Ok(len) if len >= 0xC0 => {
                return Err(DecodeError::InvalidData(
                    len as u32,
                    "DNS compression pointer not allowed in Client FQDN",
                ));
            }
            Ok(len) => {
                name = name.append_label(decoder.read_slice(len as usize)?)?;
            }
            Err(_) => break,
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fqdn_flags() {
        let mut flag = FqdnFlags::default();
        assert_eq!(flag.0, 0);
        flag.set_s_mut(true);
        // passing true clears the s bit
        flag.set_n_mut(true);
        assert!(flag.n());
        assert!(!flag.s());
        assert_eq!(flag.0, 0x04);

        flag.set_n_mut(false);
        assert!(!flag.n());
        assert!(!flag.s());
        assert_eq!(flag.0, 0x00);

        let flag = FqdnFlags::new(0x40).set_s(true);
        assert!(flag.s());
        assert!(!flag.n());
        assert!(!flag.o());
        assert_eq!(flag.0, 0x41);

        let mut flag = flag.set_o(true);
        assert!(flag.o() && flag.s());
        flag.set_o_mut(false);
        assert_eq!(flag.0, 0x41);

        flag.set_s_mut(false);
        assert_eq!(flag.0, 0x40);
        assert!(!flag.s());

        let flag = FqdnFlags::default().set_n(true).set_s(true);
        // set_s after set_n is allowed at the raw-bit level; set_n is what
        // enforces N=1 ⇒ S=0.
        assert!(flag.n() && flag.s());
        assert_eq!(flag.0, 0x05);

        let flag = FqdnFlags::default().set_s(true).set_n(true);
        assert!(flag.n());
        assert!(!flag.s());
        assert_eq!(flag.0, 0x04);
    }
}
