use core::fmt;

use {
    aead::{NewAead, AeadInPlace, AeadCore},
    generic_array::GenericArray,
};

use super::config::{Config, ConfigExt};

pub type Tag<C> = GenericArray<u8, <<C as Config>::Aead as AeadCore>::TagSize>;
pub type Aead<C> = GenericArray<u8, <<C as Config>::Aead as NewAead>::KeySize>;

#[derive(Debug)]
pub struct MacMismatch;

impl fmt::Display for MacMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mac mismatch")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacMismatch {}

pub struct CipherInner<C, const SEND: bool>
where
    C: Config,
{
    key: C::Aead,
}

impl<C, const SEND: bool> Clone for CipherInner<C, SEND>
where
    C: Config,
    C::Aead: Clone,
{
    fn clone(&self) -> Self {
        CipherInner {
            key: self.key.clone(),
        }
    }
}

impl<C> CipherInner<C, true>
where
    C: ConfigExt,
{
    /// # Panics
    ///
    /// when `buffer` slice is too long (gigabytes)
    pub fn encrypt(&self, n: u64, ad: &[u8], buffer: &mut [u8]) -> Tag<C> {
        self.key
            .encrypt_in_place_detached(&C::prepare_nonce(n), ad, buffer)
            .unwrap()
    }
}

impl<C> CipherInner<C, false>
where
    C: Config,
{
    /// # Errors
    /// mac mismatch
    pub fn decrypt(
        &self,
        n: u64,
        ad: &[u8],
        buffer: &mut [u8],
        tag: &Tag<C>,
    ) -> Result<(), MacMismatch> {
        self.key
            .decrypt_in_place_detached(&C::prepare_nonce(n), ad, buffer, tag)
            .map_err(|_| MacMismatch)
    }
}

pub struct Cipher<C, const STEP: u64, const SEND: bool>
where
    C: Config,
{
    inner: CipherInner<C, SEND>,
    nonce: u64,
}

impl<C, const STEP: u64, const SEND: bool> Clone for Cipher<C, STEP, SEND>
where
    C: Config,
    CipherInner<C, SEND>: Clone,
{
    fn clone(&self) -> Self {
        Cipher {
            inner: self.inner.clone(),
            nonce: self.nonce,
        }
    }
}

impl<C, const STEP: u64, const SEND: bool> Cipher<C, STEP, SEND>
where
    C: Config,
{
    pub(crate) fn new(key: &Aead<C>) -> Self {
        Cipher {
            inner: CipherInner {
                key: C::Aead::new(key),
            },
            nonce: 0,
        }
    }

    const fn inner(&self) -> &CipherInner<C, SEND> {
        &self.inner
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
}

impl<C, const SEND: bool> Cipher<C, 2, SEND>
where
    C: Config,
{
    /// # Panics
    ///
    /// when `data` slice is too long (gigabytes)
    pub fn link(&mut self, nonce: u64, data: &mut [u8]) {
        self.inner
            .key
            .encrypt_in_place_detached(&C::prepare_nonce(nonce * 2 + 1), &[], data)
            .unwrap();
    }
}

impl<const STEP: u64, C> Cipher<C, STEP, true>
where
    C: Config,
{
    pub fn encrypt(&mut self, ad: &[u8], buffer: &mut [u8]) -> Tag<C> {
        let tag = self.inner().encrypt(self.nonce * STEP, ad, buffer);
        self.nonce += 1;
        tag
    }

    // #[cfg(test)]
    pub fn swap(self) -> Cipher<C, STEP, false> {
        Cipher {
            inner: CipherInner {
                key: self.inner.key,
            },
            nonce: self.nonce,
        }
    }
}

impl<const STEP: u64, C> Cipher<C, STEP, false>
where
    C: Config,
{
    /// # Errors
    /// mac mismatch
    pub fn decrypt(
        &mut self,
        ad: &[u8],
        buffer: &mut [u8],
        tag: &Tag<C>,
    ) -> Result<(), MacMismatch> {
        self.inner()
            .decrypt(self.nonce * STEP, ad, buffer, tag)
            .map(|()| self.nonce += 1)
    }

    // #[cfg(test)]
    pub fn swap(self) -> Cipher<C, STEP, true> {
        Cipher {
            inner: CipherInner {
                key: self.inner.key,
            },
            nonce: self.nonce,
        }
    }
}
