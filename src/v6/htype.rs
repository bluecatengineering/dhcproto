/// In DHCPv6, the Hardware Types are expanded from u8 to u16, referring to https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml for implementation.
use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hardware type of message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Hash, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct HType(pub u16);

#[allow(non_upper_case_globals)]
impl HType {
    /// 1 Ethernet
    pub const Eth: Self = Self(1);
    /// 2 Experimental Ethernet
    pub const ExperimentalEth: Self = Self(2);
    /// 3 Amateur Radio AX25
    pub const AmRadioAX25: Self = Self(3);
    /// 4 Proteon Token Ring
    pub const ProteonTokenRing: Self = Self(4);
    /// 5 Chaos
    pub const Chaos: Self = Self(5);
    /// 6 IEEE.802
    pub const IEEE802: Self = Self(6);
    /// 7 ARCNET
    pub const ARCNET: Self = Self(7);
    /// 8 Hyperchannel
    pub const Hyperchannel: Self = Self(8);
    /// 9 LANSTAR
    pub const Lanstar: Self = Self(9);
    /// 10 Autonet Short Addr
    pub const AutonetShortAddr: Self = Self(10);
    /// 11 LocalTalk
    pub const LocalTalk: Self = Self(11);
    /// 12 LocalNet
    pub const LocalNet: Self = Self(12);
    /// 13 Ultralink
    pub const Ultralink: Self = Self(13);
    /// 14 SMDS
    pub const SMDS: Self = Self(14);
    /// 15 FrameRelay
    pub const FrameRelay: Self = Self(15);
    /// 17 HDLC
    pub const HDLC: Self = Self(17);
    /// 18 FibreChannel
    pub const FibreChannel: Self = Self(18);
    /// 20 SerialLine
    pub const SerialLine: Self = Self(20);
    /// 22 Mil STD
    pub const MilStd188220: Self = Self(22);
    /// 23 Metricom
    pub const Metricom: Self = Self(23);
    /// 24 IEEE1394.1995
    pub const IEEE13941995: Self = Self(24);
    /// 25 MAPOS
    pub const MAPOS: Self = Self(25);
    /// 26 Twinaxial
    pub const Twinaxial: Self = Self(26);
    /// 27 EUI64
    pub const EUI64: Self = Self(27);
    /// 28 HIPARP
    pub const HIPARP: Self = Self(28);
    /// 29 IP and ARP over ISO 7816-3
    pub const IPandARPoverISO78163: Self = Self(29);
    /// 30 ARPSec
    pub const ARPSec: Self = Self(30);
    /// 31 IPsec tunnel
    pub const IPsecTunnel: Self = Self(31);
    /// 32 Infiniband
    pub const Infiniband: Self = Self(32);
    /// 33 TIA-102 Project 25 Common Air Interface (CAI)
    pub const CAI: Self = Self(33);
    /// 34 WeigandInt
    pub const WiegandInt: Self = Self(34);
    /// 35 PureIP
    pub const PureIP: Self = Self(35);
    /// 36 HW_EXP1
    pub const HWExp1: Self = Self(36);
    /// 37 HFI
    pub const HFI: Self = Self(37);
    /// 38 Unified BUS(UB)
    pub const UB: Self = Self(38);
    /// 256 HW_EXP2
    pub const HWExp2: Self = Self(256);
    /// 257 AEthernet
    pub const AEthernet: Self = Self(257);
    /// 65535 Reserved
    pub const Reserved: Self = Self(65535);
}

impl From<u16> for HType {
    fn from(n: u16) -> Self {
        Self(n)
    }
}

impl From<HType> for u16 {
    fn from(n: HType) -> Self {
        n.0
    }
}

impl Decodable for HType {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(decoder.read_u16()?.into())
    }
}

impl Encodable for HType {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u16((*self).into())
    }
}
