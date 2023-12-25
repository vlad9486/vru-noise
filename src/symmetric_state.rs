use core::{marker::PhantomData, ops::Add};

use {
    aead::{KeyInit, AeadInPlace, KeySizeUser},
    generic_array::{
        GenericArray,
        typenum::{self, Unsigned},
    },
    zeroize::Zeroize,
};

use super::{
    config::{Config, ConfigExt},
    hash::{MixHash, HkdfSplitExt},
    cipher_state::{MacMismatch, Tag, Cipher},
};

pub struct Output<C, const STEP: u64>
where
    C: Config,
{
    pub sender: Cipher<C, STEP, true>,
    pub receiver: Cipher<C, STEP, false>,
    pub hash: Hash<C>,
}

#[derive(Clone)]
pub struct OutputRaw<C>
where
    C: Config,
{
    pub sender: GenericArray<u8, <C::Aead as KeySizeUser>::KeySize>,
    pub receiver: GenericArray<u8, <C::Aead as KeySizeUser>::KeySize>,
    pub hash: Hash<C>,
}

pub struct Key<C, N>
where
    C: Config,
    N: Unsigned,
{
    chaining_key: ChainingKey<C>,
    aead: C::Aead,
    nonce: PhantomData<N>,
}

impl<C, N> From<Key<C, N>> for ChainingKey<C>
where
    C: Config,
    N: Unsigned,
{
    fn from(v: Key<C, N>) -> Self {
        v.chaining_key
    }
}

impl<C, N> Key<C, N>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    #[allow(clippy::missing_const_for_fn)]
    fn increase(self) -> Key<C, <N as Add<typenum::U1>>::Output> {
        let Key {
            chaining_key, aead, ..
        } = self;
        Key {
            chaining_key,
            aead,
            nonce: PhantomData,
        }
    }
}

type SymmetricStateNext<C, N> = SymmetricState<C, Key<C, <N as Add<typenum::U1>>::Output>>;
type Hash<C> = GenericArray<u8, <<C as Config>::MixHash as MixHash>::L>;
pub type ChainingKey<C> = GenericArray<u8, <<C as Config>::MixHash as MixHash>::L>;

#[derive(Clone)]
pub struct SymmetricState<C, K>
where
    C: Config,
{
    key: K,
    hash: Hash<C>,
}

impl<C> SymmetricState<C, ChainingKey<C>>
where
    C: Config,
{
    #[must_use]
    pub fn new(name: &str) -> Self {
        let length = name.as_bytes().len();
        let size = <C::MixHash as MixHash>::L::USIZE;
        let hash = if length <= size {
            let mut array = GenericArray::default();
            array[0..length].copy_from_slice(name.as_bytes());
            array
        } else {
            C::MixHash::init(name.as_bytes())
        };

        SymmetricState {
            key: hash.clone(),
            hash,
        }
    }
}

impl<C, K> SymmetricState<C, K>
where
    C: Config,
{
    pub fn hash(&self) -> Hash<C> {
        self.hash.clone()
    }

    #[must_use]
    pub fn mix_hash(self, data: &[u8]) -> Self {
        let SymmetricState { key, hash } = self;
        let hash = C::MixHash::mix_hash(hash, data);
        SymmetricState { key, hash }
    }
}

impl<C, K> SymmetricState<C, K>
where
    C: Config,
    K: Into<ChainingKey<C>>,
{
    pub fn mix_shared_secret<S>(self, mut data: S) -> SymmetricState<C, Key<C, typenum::U0>>
    where
        S: AsRef<[u8]> + Zeroize,
    {
        let SymmetricState { key, hash } = self;

        let chaining_key = key.into();
        let (chaining_key, mut aead) = C::HkdfSplit::split_2(&chaining_key, data.as_ref());
        data.zeroize();
        let key = Key {
            chaining_key,
            aead: C::Aead::new(&aead),
            nonce: PhantomData,
        };
        aead.zeroize();
        SymmetricState { key, hash }
    }

    pub fn mix_psk<S>(self, mut data: S) -> SymmetricState<C, Key<C, typenum::U0>>
    where
        S: AsRef<[u8]> + Zeroize,
    {
        let SymmetricState { key, hash } = self;

        let chaining_key = key.into();
        let (chaining_key, middle, mut aead) = C::HkdfSplit::split_3(&chaining_key, data.as_ref());
        data.zeroize();
        let key = Key {
            chaining_key,
            aead: C::Aead::new(&aead),
            nonce: PhantomData,
        };
        aead.zeroize();
        let hash = C::MixHash::mix_hash(hash, middle.as_ref());
        SymmetricState { key, hash }
    }

    pub fn finish_raw<const STEP: u64, const SWAP: bool>(self) -> OutputRaw<C> {
        let mut c = self.key.into();
        let (send_key, receive_key) = C::HkdfSplit::split_final(&c, &[]);
        c.zeroize();
        if SWAP {
            OutputRaw {
                sender: receive_key,
                receiver: send_key,
                hash: self.hash,
            }
        } else {
            OutputRaw {
                sender: send_key,
                receiver: receive_key,
                hash: self.hash,
            }
        }
    }

    pub fn finish<const STEP: u64, const SWAP: bool>(self) -> Output<C, STEP> {
        let mut c = self.key.into();
        let (mut send_key, mut receive_key) = C::HkdfSplit::split_final(&c, &[]);
        c.zeroize();
        let r = if SWAP {
            Output {
                sender: Cipher::new(&receive_key),
                receiver: Cipher::new(&send_key),
                hash: self.hash,
            }
        } else {
            Output {
                sender: Cipher::new(&send_key),
                receiver: Cipher::new(&receive_key),
                hash: self.hash,
            }
        };
        send_key.zeroize();
        receive_key.zeroize();
        r
    }
}

impl<C, N> SymmetricState<C, Key<C, N>>
where
    C: ConfigExt,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    pub fn increase(self) -> SymmetricStateNext<C, N> {
        SymmetricState {
            key: self.key.increase(),
            hash: self.hash,
        }
    }

    /// # Panics
    ///
    /// when `zeros` slice is too long (gigabytes)
    pub fn zeros_tag<const L: usize>(
        self,
        zeros: &mut [u8; L],
    ) -> (SymmetricStateNext<C, N>, Tag<C>) {
        // hope it will be optimized
        let nonce = C::prepare_nonce(N::U64);
        self.key
            .aead
            .encrypt_in_place_detached(&nonce, &self.hash, zeros)
            .unwrap();
        let mut data = *zeros;
        let tag = self
            .key
            .aead
            .encrypt_in_place_detached(&nonce, &self.hash, &mut data)
            .unwrap();
        (
            SymmetricState {
                key: self.key.increase(),
                hash: C::MixHash::mix_parts(self.hash, &[&data, &tag]),
            },
            tag,
        )
    }

    /// # Panics
    ///
    /// when `data` slice is too long (gigabytes)
    pub fn encrypt(self, data: &mut [u8]) -> (SymmetricStateNext<C, N>, Tag<C>) {
        let tag = self
            .key
            .aead
            .encrypt_in_place_detached(&C::prepare_nonce(N::U64), &self.hash, data)
            .unwrap();
        (
            SymmetricState {
                key: self.key.increase(),
                hash: C::MixHash::mix_parts(self.hash, &[data, &tag]),
            },
            tag,
        )
    }

    #[cfg(feature = "alloc")]
    pub fn encrypt_ext(self, data: &mut alloc::vec::Vec<u8>) -> SymmetricStateNext<C, N> {
        let (state, tag) = self.encrypt(data);
        data.extend_from_slice(&tag);
        state
    }

    /// # Errors
    /// mac mismatch
    pub fn decrypt(
        self,
        data: &mut [u8],
        tag: &Tag<C>,
    ) -> Result<SymmetricStateNext<C, N>, MacMismatch> {
        let hash = C::MixHash::mix_parts(self.hash.clone(), &[data, tag]);
        self.key
            .aead
            .decrypt_in_place_detached(&C::prepare_nonce(N::U64), &self.hash, data, tag)
            .map(|()| SymmetricState {
                key: self.key.increase(),
                hash,
            })
            .map_err(|_| MacMismatch)
    }
}

#[cfg(feature = "serde")]
mod serde_m {
    use core::{mem, fmt};
    use alloc::string::String;

    use aead::KeySizeUser;
    use generic_array::{GenericArray, typenum::Unsigned};
    use serde::{Serialize, Deserialize};

    use super::{SymmetricState, ChainingKey, Config, Hash, OutputRaw};

    #[derive(Serialize, Deserialize, Debug)]
    struct Inner {
        key: String,
        hash: String,
    }

    impl<C> SymmetricState<C, ChainingKey<C>>
    where
        C: Config,
    {
        fn as_inner(&self) -> Inner {
            Inner {
                key: hex::encode(&self.key),
                hash: hex::encode(&self.hash),
            }
        }
    }

    impl<'de, C> TryFrom<Inner> for SymmetricState<C, ChainingKey<C>>
    where
        C: Config,
    {
        type Error = hex::FromHexError;

        fn try_from(Inner { key, hash }: Inner) -> Result<Self, Self::Error> {
            let key = hex::decode(key).and_then(|v| {
                if v.len() == mem::size_of::<ChainingKey<C>>() {
                    Ok(GenericArray::from_slice(&v).clone())
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })?;
            let hash = hex::decode(hash).and_then(|v| {
                if v.len() == mem::size_of::<Hash<C>>() {
                    Ok(GenericArray::from_slice(&v).clone())
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })?;
            Ok(SymmetricState { key, hash })
        }
    }

    impl<'de, C> Deserialize<'de> for SymmetricState<C, ChainingKey<C>>
    where
        C: Config,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Inner::deserialize(deserializer)?
                .try_into()
                .map_err(serde::de::Error::custom)
        }
    }

    impl<C> Serialize for SymmetricState<C, ChainingKey<C>>
    where
        C: Config,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.as_inner().serialize(serializer)
        }
    }

    impl<C> fmt::Debug for SymmetricState<C, ChainingKey<C>>
    where
        C: Config,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.as_inner(), f)
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct OutputInner {
        sender: String,
        receiver: String,
        hash: String,
    }

    impl<C> OutputRaw<C>
    where
        C: Config,
    {
        fn as_inner(&self) -> OutputInner {
            OutputInner {
                sender: hex::encode(&self.sender),
                receiver: hex::encode(&self.receiver),
                hash: hex::encode(&self.hash),
            }
        }
    }

    impl<'de, C> TryFrom<OutputInner> for OutputRaw<C>
    where
        C: Config,
    {
        type Error = hex::FromHexError;

        fn try_from(
            OutputInner {
                sender,
                receiver,
                hash,
            }: OutputInner,
        ) -> Result<Self, Self::Error> {
            let key_size = <<C::Aead as KeySizeUser>::KeySize as Unsigned>::USIZE;

            let sender = hex::decode(sender).and_then(|v| {
                if v.len() == key_size {
                    Ok(GenericArray::from_slice(&v).clone())
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })?;
            let receiver = hex::decode(receiver).and_then(|v| {
                if v.len() == key_size {
                    Ok(GenericArray::from_slice(&v).clone())
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })?;
            let hash = hex::decode(hash).and_then(|v| {
                if v.len() == mem::size_of::<Hash<C>>() {
                    Ok(GenericArray::from_slice(&v).clone())
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })?;
            Ok(OutputRaw {
                sender,
                receiver,
                hash,
            })
        }
    }

    impl<'de, C> Deserialize<'de> for OutputRaw<C>
    where
        C: Config,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            OutputInner::deserialize(deserializer)?
                .try_into()
                .map_err(serde::de::Error::custom)
        }
    }

    impl<C> Serialize for OutputRaw<C>
    where
        C: Config,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.as_inner().serialize(serializer)
        }
    }

    impl<C> fmt::Debug for OutputRaw<C>
    where
        C: Config,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.as_inner(), f)
        }
    }
}
