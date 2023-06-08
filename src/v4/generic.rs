use std::{collections::HashMap, hash::Hash};

use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::{DecodeResult, EncodeResult},
    v4::OptionCode,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Map of Unknown options
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericOptions<K: Eq + Hash, V>(HashMap<K, V>);

impl<K: Eq + Hash, V> Default for GenericOptions<K, V> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

/// trait to get the hashmap identifier for a given value
pub trait Id<K> {
    fn id(&self) -> K;
}

impl<K, V> GenericOptions<K, V>
where
    K: Hash + Eq,
    V: Encodable + Decodable + Id<K>,
{
    /// Get the data
    pub fn get(&self, code: K) -> Option<&V> {
        self.0.get(&code)
    }
    /// Get the mutable data
    pub fn get_mut(&mut self, code: K) -> Option<&mut V> {
        self.0.get_mut(&code)
    }
    /// remove sub option
    pub fn remove(&mut self, code: K) -> Option<V> {
        self.0.remove(&code)
    }
    /// insert
    pub fn insert(&mut self, item: V) -> Option<V> {
        self.0.insert(item.id(), item)
    }
    /// iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.0.iter()
    }
    /// iterate mutably over entries
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
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
        F: FnMut(&K, &mut V) -> bool,
    {
        self.0.retain(pred)
    }
}

impl<K: Eq + Hash, V: Decodable + Id<K>> Decodable for GenericOptions<K, V> {
    fn decode(d: &mut crate::Decoder<'_>) -> super::DecodeResult<Self> {
        let mut opts = HashMap::new();
        while let Ok(opt) = V::decode(d) {
            opts.insert(opt.id(), opt);
        }
        Ok(Self(opts))
    }
}

impl<K: Eq + Hash, V: Encodable + Id<K>> Encodable for GenericOptions<K, V> {
    fn encode(&self, e: &mut crate::Encoder<'_>) -> super::EncodeResult<()> {
        self.0.iter().try_for_each(|(_, info)| info.encode(e))
    }
}

impl Id<u8> for UnknownOption {
    fn id(&self) -> u8 {
        self.code
    }
}

impl<K, V> IntoIterator for GenericOptions<K, V>
where
    K: Eq + Hash,
{
    type Item = (K, V);
    type IntoIter = std::collections::hash_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<UnknownOption> for GenericOptions<u8, UnknownOption> {
    fn from_iter<T: IntoIterator<Item = UnknownOption>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|opt| (opt.id(), opt))
                .collect::<HashMap<u8, UnknownOption>>(),
        )
    }
}

impl<K, V> FromIterator<(K, V)> for GenericOptions<K, V>
where
    K: Eq + Hash,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(iter.into_iter().collect::<HashMap<_, _>>())
    }
}

/// An as-of-yet unimplemented option type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption {
    pub(crate) code: u8,
    pub(crate) data: Vec<u8>,
}

impl UnknownOption {
    pub fn new<C, D>(code: C, data: D) -> Self
    where
        C: Into<u8>,
        D: Into<Vec<u8>>,
    {
        Self {
            code: code.into(),
            data: data.into(),
        }
    }
    /// return the option code
    pub fn code(&self) -> OptionCode {
        self.code.into()
    }
    /// return the data for this option
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// consume into parts
    pub fn into_parts(self) -> (OptionCode, Vec<u8>) {
        (self.code.into(), self.data)
    }
}

impl Decodable for UnknownOption {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let code = decoder.read_u8()?;
        let length = decoder.read_u8()?;
        let bytes = decoder.read_slice(length as usize)?.to_vec();
        Ok(UnknownOption { code, data: bytes })
    }
}

impl Encodable for UnknownOption {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        // TODO: account for >255 len
        e.write_u8(self.code)?;
        e.write_u8(self.data.len() as u8)?;
        e.write_slice(&self.data)?;
        Ok(())
    }
}
