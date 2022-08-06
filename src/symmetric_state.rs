use core::{marker::PhantomData, ops::Add};

use {
    aead::{KeyInit, AeadInPlace},
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
    pub hash: GenericArray<u8, <C::MixHash as MixHash>::L>,
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
