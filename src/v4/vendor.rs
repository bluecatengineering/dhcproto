//! vendor
use std::collections::HashMap;

use crate::{
    v4::generic::{GenericOptions, UnknownOption},
    Decodable, Encodable,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Collection of vendor classes
/// https://www.rfc-editor.org/rfc/rfc3925#section-3
///
/// You can create/modify it, then insert into a message opts section
/// in [`DhcpOption::VendorData]
///
/// ```rust
/// use dhcproto::v4::{self, vendor::{VendorData, VendorClasses}};
///
/// let mut info = VendorClasses::default();
/// info.insert(VendorData::new(1234, b"docsis3.0"));
/// let mut opts = v4::DhcpOptions::default();
/// opts
///     .insert(v4::DhcpOption::VendorClasses(info));
/// ```
///
/// [`DhcpOption::VendorClasses`]: crate::v4::DhcpOption::VendorClasses
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VendorClasses(HashMap<EnterpriseId, Vec<Vec<u8>>>);

pub type EnterpriseId = u32;

impl VendorClasses {
    /// Get the data for a particular [`EnterpriseId`]
    ///
    /// [`EnterpriseId`]: crate::v4::vendor:EnterpriseId:
    pub fn get(&self, code: EnterpriseId) -> Option<&[Vec<u8>]> {
        self.0.get(&code)
    }
    /// Get the mutable data for a particular [`EnterpriseId`]
    ///
    /// [`EnterpriseId`]: crate::v4::vendor::EnterpriseId
    pub fn get_mut(&mut self, code: EnterpriseId) -> Option<&mut Vec<Vec<u8>>> {
        self.0.get_mut(&code)
    }
    /// remove sub option
    pub fn remove(&mut self, code: EnterpriseId) -> Option<Vec<Vec<u8>>> {
        self.0.remove(&code)
    }
    /// insert a new [`VendorData`]
    ///
    /// [`VendorData`]: crate::v4::relay::VendorData
    pub fn insert(&mut self, info: VendorData) -> Option<VendorData> {
        self.0.insert(info.id, info)
    }
    /// iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = (&EnterpriseId, &VendorData)> {
        self.0.iter()
    }
    /// iterate mutably over entries
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&EnterpriseId, &mut VendorData)> {
        self.0.iter_mut()
    }
    /// clear all options
    pub fn clear(&mut self) {
        self.0.clear()
    }
    /// Returns `true` if there are no options
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns number of relay agent
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Retans only the elements specified by the predicate
    pub fn retain<F>(&mut self, pred: F)
    where
        F: FnMut(&EnterpriseId, &mut VendorData) -> bool,
    {
        self.0.retain(pred)
    }
}

impl Decodable for VendorClasses {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let mut opts = HashMap::new();
        while let Ok(opt) = VendorData::decode(d) {
            opts.insert(opt.id, opt);
        }
        Ok(Self(opts))
    }
}

impl Encodable for VendorClasses {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        self.0.iter().try_for_each(|(_, info)| info.encode(e))
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorData {
    id: EnterpriseId,
    data: Vec<Vec<u8>>,
}

impl VendorData {
    pub fn new<T: Into<Vec<u8>>>(id: EnterpriseId, data: T) -> Self {
        Self {
            id,
            data: data.into(),
        }
    }
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn enterprise_id(&self) -> u32 {
        self.id
    }
    /// consume into parts
    pub fn into_parts(self) -> (EnterpriseId, Vec<u8>) {
        (self.id, self.data)
    }
}

#[inline]
fn decode_data(decoder: &'_ mut Decoder<'_>) -> Vec<Vec<u8>> {
    let mut data = Vec::new();
    while let Ok(len) = decoder.read_u16() {
        // if we can read the len and the string
        match decoder.read_slice(len as usize) {
            Ok(s) => data.push(s.to_vec()),
            // push, otherwise stop
            _ => break,
        }
    }
    data
}



impl Decodable for VendorData {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let id = d.read_u32()?;
        let len = d.read_u8()?;
        let data = d.read_slice(len as usize)?.to_vec();
        Ok(Self { id, data })
    }
}

impl Encodable for VendorData {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        e.write_u32(self.id)?;
        e.write_u8(self.data.len() as u8)?;
        e.write_slice(&self.data)?;

        Ok(())
    }
}

/// Collection of vendor options. For each enterprise id, there is a collection
/// of options data potentially.
/// https://www.rfc-editor.org/rfc/rfc3925#section-4
///
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VendorOptions(HashMap<EnterpriseId, GenericOptions<u8, UnknownOption>>);

impl VendorOptions {
    /// Get the data for a particular [`EnterpriseId`]
    ///
    /// [`EnterpriseId`]: crate::v4::vendor:EnterpriseId
    pub fn get(&self, code: EnterpriseId) -> Option<&GenericOptions<u8, UnknownOption>> {
        self.0.get(&code)
    }
    /// Get the mutable data for a particular [`EnterpriseId`]
    ///
    /// [`EnterpriseId`]: crate::v4::vendor::EnterpriseId
    pub fn get_mut(
        &mut self,
        code: EnterpriseId,
    ) -> Option<&mut GenericOptions<u8, UnknownOption>> {
        self.0.get_mut(&code)
    }
    /// remove sub option
    pub fn remove(&mut self, code: EnterpriseId) -> Option<GenericOptions<u8, UnknownOption>> {
        self.0.remove(&code)
    }
    /// insert a new [`VendorClass`]
    ///
    /// [`VendorClass`]: crate::v4::relay::VendorClass
    pub fn insert(
        &mut self,
        id: EnterpriseId,
        info: GenericOptions<u8, UnknownOption>,
    ) -> Option<GenericOptions<u8, UnknownOption>> {
        self.0.insert(id, info)
    }
    /// iterate over entries
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&EnterpriseId, &GenericOptions<u8, UnknownOption>)> {
        self.0.iter()
    }
    /// iterate mutably over entries
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&EnterpriseId, &mut GenericOptions<u8, UnknownOption>)> {
        self.0.iter_mut()
    }
    /// clear all options
    pub fn clear(&mut self) {
        self.0.clear()
    }
    /// Returns `true` if there are no options
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns number of relay agent
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Retans only the elements specified by the predicate
    pub fn retain<F>(&mut self, pred: F)
    where
        F: FnMut(&EnterpriseId, &mut GenericOptions<u8, UnknownOption>) -> bool,
    {
        self.0.retain(pred)
    }
}

impl Decodable for VendorOptions {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let mut opts = HashMap::new();
        while let Ok(id) = d.read_u32() {

            opts.insert(id, {

                let mut sub_opts = 
                GenericOptions::decode(d)?});
        }
        Ok(Self(opts))
    }
}

impl Encodable for VendorOptions {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        self.0.iter().try_for_each(|(code, data)| {
            e.write_u32(*code)?;
                let mut buf = Vec::new();
                let mut opt_enc = Encoder::new(&mut buf);
                classes.encode(&mut opt_enc)?;
                // data encoded to intermediate buf
                encode_long_opt_bytes(code, &buf, e)?;
            data.encode(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Encoder;

    use super::*;

    #[test]
    fn test_vendor_class() {
        let mut info = VendorClasses::default();

        info.insert(VendorData::new(1234, &b"docsis3.0"[..]));
        let snd = VendorData::new(4321, &b"foobar"[..]);

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        info.encode(&mut e).unwrap();

        let id = 1234_u32.to_be_bytes();
        let b = 4321_u32.to_be_bytes();

        let mut snd_buf = Vec::new();
        let mut e = Encoder::new(&mut snd_buf);
        snd.encode(&mut e).unwrap();

        assert_eq!(
            &buf,
            &[id[0], id[1], id[2], id[3], 9, b'd', b'o', b'c', b's', b'i', b's', b'3', b'.', b'0']
        );
        // second data
        assert_eq!(
            &snd_buf,
            &[b[0], b[1], b[2], b[3], 6, b'f', b'o', b'o', b'b', b'a', b'r']
        );
    }

    #[test]
    fn test_vendor_opts() {
        let mut info = VendorOptions::default();

        info.insert(1234, {
            let mut fst = GenericOptions::default();
            fst.insert(UnknownOption::new(10, &b"docsis3.0"[..]));
            fst
        });

        info.insert(4321, {
            let mut fst = GenericOptions::default();
            fst.insert(UnknownOption::new(11, &b"foobar"[..]));
            fst
        });

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        info.encode(&mut e).unwrap();
        let id = 1234_u32.to_be_bytes();
        let b = 4321_u32.to_be_bytes();

        println!("{buf:?}");
        println!(
            "{:?}",
            // <e-id><len><sub-code><sub-len><sub-data>
            [b[0], b[1], b[2], b[3], 11, 6, b'f', b'o', b'o', b'b', b'a', b'r']
        );
        assert!(&buf.windows(9 + 5).any(|win| win
            == [
                id[0], id[1], id[2], id[3], 9, b'd', b'o', b'c', b's', b'i', b's', b'3', b'.', b'0'
            ]));
        assert!(&buf
            .windows(6 + 5)
            .any(|win| win == [b[0], b[1], b[2], b[3], 11, 6, b'f', b'o', b'o', b'b', b'a', b'r']));
    }
}
