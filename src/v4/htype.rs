use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
};

use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hardware type of message
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive)]
#[num_enum(u8)]
pub enum HType {
    /// 1 Ethernet
    #[num_enum(num = 1)]
    Eth,
    /// 2 Experimental Ethernet
    #[num_enum(num = 2)]
    ExperimentalEth,
    /// 3 Amateur Radio AX25
    #[num_enum(num = 3)]
    AmRadioAX25,
    /// 4 Proteon Token Ring
    #[num_enum(num = 4)]
    ProteonTokenRing,
    /// 5 Chaos
    #[num_enum(num = 5)]
    Chaos,
    /// 6 IEEE.802
    #[num_enum(num = 6)]
    IEEE802,
    /// 7 ARCNET
    #[num_enum(num = 7)]
    ARCNET,
    /// 8 Hyperchannel
    #[num_enum(num = 8)]
    Hyperchannel,
    /// 9 LANSTAR
    #[num_enum(num = 9)]
    Lanstar,
    /// 10 Autonet Short Addr
    #[num_enum(num = 10)]
    AutonetShortAddr,
    /// 11 LocalTalk
    #[num_enum(num = 11)]
    LocalTalk,
    /// 12 LocalNet
    #[num_enum(num = 12)]
    LocalNet,
    /// 13 Ultralink
    #[num_enum(num = 13)]
    Ultralink,
    /// 14 SMDS
    #[num_enum(num = 14)]
    SMDS,
    /// 15 FrameRelay
    #[num_enum(num = 15)]
    FrameRelay,
    /// 17 HDLC
    #[num_enum(num = 17)]
    HDLC,
    /// 18 FibreChannel
    #[num_enum(num = 18)]
    FibreChannel,
    /// 20 SerialLine
    #[num_enum(num = 20)]
    SerialLine,
    /// 22 Mil STD
    #[num_enum(num = 22)]
    MilStd188220,
    /// 23 Metricom
    #[num_enum(num = 23)]
    Metricom,
    /// 25 MAPOS
    #[num_enum(num = 25)]
    MAPOS,
    /// 26 Twinaxial
    #[num_enum(num = 26)]
    Twinaxial,
    /// 30 ARPSec
    #[num_enum(num = 30)]
    ARPSec,
    /// 31 IPsec tunnel
    #[num_enum(num = 31)]
    IPsecTunnel,
    /// 32 Infiniband
    #[num_enum(num = 32)]
    Infiniband,
    /// 34 WeigandInt
    #[num_enum(num = 34)]
    WiegandInt,
    /// 35 PureIP
    #[num_enum(num = 35)]
    PureIP,
    /// Unknown or not yet implemented htype
    #[num_enum(catch_all)]
    Unknown(u8),
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
