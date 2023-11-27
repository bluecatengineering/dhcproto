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
pub enum HType {
    /// 1 Ethernet
    Eth,
    /// 2 Experimental Ethernet
    ExperimentalEth,
    /// 3 Amateur Radio AX25
    AmRadioAX25,
    /// 4 Proteon Token Ring
    ProteonTokenRing,
    /// 5 Chaos
    Chaos,
    /// 6 IEEE.802
    IEEE802,
    /// 7 ARCNET
    ARCNET,
    /// 8 Hyperchannel
    Hyperchannel,
    /// 9 LANSTAR
    Lanstar,
    /// 10 Autonet Short Addr
    AutonetShortAddr,
    /// 11 LocalTalk
    LocalTalk,
    /// 12 LocalNet
    LocalNet,
    /// 13 Ultralink
    Ultralink,
    /// 14 SMDS
    SMDS,
    /// 15 FrameRelay
    FrameRelay,
    /// 17 HDLC
    HDLC,
    /// 18 FibreChannel
    FibreChannel,
    /// 20 SerialLine
    SerialLine,
    /// 22 Mil STD
    MilStd188220,
    /// 23 Metricom
    Metricom,
    /// 25 MAPOS
    MAPOS,
    /// 26 Twinaxial
    Twinaxial,
    /// 30 ARPSec
    ARPSec,
    /// 31 IPsec tunnel
    IPsecTunnel,
    /// 32 Infiniband
    Infiniband,
    /// 34 WeigandInt
    WiegandInt,
    /// 35 PureIP
    PureIP,
    /// Unknown or not yet implemented htype
    Unknown(u8),
}

impl From<u8> for HType {
    fn from(n: u8) -> Self {
        use HType::*;
        match n {
            1 => Eth,
            2 => ExperimentalEth,
            3 => AmRadioAX25,
            4 => ProteonTokenRing,
            5 => Chaos,
            6 => IEEE802,
            7 => ARCNET,
            8 => Hyperchannel,
            9 => Lanstar,
            10 => AutonetShortAddr,
            11 => LocalTalk,
            12 => LocalNet,
            13 => Ultralink,
            14 => SMDS,
            15 => FrameRelay,
            17 => HDLC,
            18 => FibreChannel,
            20 => SerialLine,
            22 => MilStd188220,
            23 => Metricom,
            25 => MAPOS,
            26 => Twinaxial,
            30 => ARPSec,
            31 => IPsecTunnel,
            32 => Infiniband,
            34 => WiegandInt,
            35 => PureIP,
            n => Unknown(n),
        }
    }
}

impl From<HType> for u8 {
    fn from(n: HType) -> Self {
        use HType as H;
        match n {
            H::Eth => 1,
            H::ExperimentalEth => 2,
            H::AmRadioAX25 => 3,
            H::ProteonTokenRing => 4,
            H::Chaos => 5,
            H::IEEE802 => 6,
            H::ARCNET => 7,
            H::Hyperchannel => 8,
            H::Lanstar => 9,
            H::AutonetShortAddr => 10,
            H::LocalTalk => 11,
            H::LocalNet => 12,
            H::Ultralink => 13,
            H::SMDS => 14,
            H::FrameRelay => 15,
            H::HDLC => 17,
            H::FibreChannel => 18,
            H::SerialLine => 20,
            H::MilStd188220 => 22,
            H::Metricom => 23,
            H::MAPOS => 25,
            H::Twinaxial => 26,
            H::ARPSec => 30,
            H::IPsecTunnel => 31,
            H::Infiniband => 32,
            H::WiegandInt => 34,
            H::PureIP => 35,
            H::Unknown(n) => n,
        }
    }
}

impl Decodable for HType {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        Ok(decoder.read_u8()?.into())
    }
}

impl Encodable for HType {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        e.write_u8((*self).into())
    }
}
