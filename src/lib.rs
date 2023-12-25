#![deny(clippy::all)]
// #![warn(clippy::cargo)]
#![allow(clippy::type_complexity)]
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

#[cfg(test)]
mod tests;

mod config;
mod hash;
mod cipher_state;
mod symmetric_state;

pub use self::config::{Config, ConfigExt};
pub use self::cipher_state::{Tag, Aead, MacMismatch, CipherInner, Cipher};
pub use self::symmetric_state::{Output, OutputRaw, Key, SymmetricState, ChainingKey};

pub use generic_array;
pub use digest;
pub use hkdf;
