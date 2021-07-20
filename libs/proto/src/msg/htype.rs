use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

/// Hardware type of message
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
        use HType::*;
        match n {
            Eth => 1,
            ExperimentalEth => 2,
            AmRadioAX25 => 3,
            ProteonTokenRing => 4,
            Chaos => 5,
            IEEE802 => 6,
            ARCNET => 7,
            Hyperchannel => 8,
            Lanstar => 9,
            AutonetShortAddr => 10,
            LocalTalk => 11,
            LocalNet => 12,
            Ultralink => 13,
            SMDS => 14,
            FrameRelay => 15,
            HDLC => 17,
            FibreChannel => 18,
            SerialLine => 20,
            MilStd188220 => 22,
            Metricom => 23,
            MAPOS => 25,
            Twinaxial => 26,
            ARPSec => 30,
            IPsecTunnel => 31,
            Infiniband => 32,
            WiegandInt => 34,
            PureIP => 35,
            Unknown(n) => n,
        }
    }
}

impl<'r> Decodable<'r> for HType {
    fn decode(decoder: &mut Decoder<'r>) -> DecodeResult<Self> {
        Ok(decoder.read_u8()?.into())
    }
}

impl<'a> Encodable<'a> for HType {
    fn encode(&self, e: &'_ mut Encoder<'a>) -> EncodeResult<()> {
        e.write_u8((*self).into())
    }
}
