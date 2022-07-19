use {
    aead::{NewAead, AeadCore, AeadInPlace, Nonce},
    generic_array::typenum::{Bit, Unsigned},
    digest::OutputSizeUser,
    hkdf::HmacImpl,
};

use super::hash::{MixHash, HkdfSplitExt};

pub trait Config {
    type BigEndianness: Bit; // LittleEndian for chacha20poly1305 and BigEndian for Aes256Gcm
    type Aead: NewAead + AeadInPlace;
    type MixHash: MixHash;
    type HkdfSplit: HkdfSplitExt<Self::Aead, L = <Self::MixHash as MixHash>::L>;
}

impl<I, D, E, A> Config for (I, D, E, A)
where
    I: HmacImpl<D>,
    (D, I): HkdfSplitExt<A, L = <D as MixHash>::L>,
    D: OutputSizeUser + MixHash,
    E: Bit,
    A: NewAead + AeadInPlace,
{
    type BigEndianness = E;
    type Aead = A;
    type MixHash = D;
    type HkdfSplit = (D, I);
}

pub trait ConfigExt
where
    Self: Config,
{
    fn prepare_nonce(n: u64) -> Nonce<Self::Aead>;
}

impl<C> ConfigExt for C
where
    C: Config,
{
    fn prepare_nonce(n: u64) -> Nonce<Self::Aead> {
        let len = <<Self::Aead as AeadCore>::NonceSize as Unsigned>::USIZE;
        let n = if <Self::BigEndianness as Bit>::BOOL {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        };
        let min = n.len().min(len);
        let mut nonce = Nonce::<Self::Aead>::default();
        nonce[(len - min)..].clone_from_slice(&n[(n.len() - min)..]);
        nonce
    }
}
