mod test_vector;
use self::test_vector::TestVector;

mod xk;

mod elliptic;
use self::elliptic::{C25519Scalar, X448Scalar};

use hkdf::hmac::{Hmac, SimpleHmac};
use sha2::{Sha256, Sha512};
use blake2::{Blake2b512, Blake2s256};
use generic_array::typenum::{B0, B1};
use chacha20poly1305::ChaCha20Poly1305;
use aes_gcm::Aes256Gcm;

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_ChaChaPoly_SHA512() {
    let vector = TestVector::try_load("Noise_XK_25519_ChaChaPoly_SHA512").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (Hmac<Sha512>, Sha512, B0, ChaCha20Poly1305)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_AESGCM_SHA512() {
    let vector = TestVector::try_load("Noise_XK_25519_AESGCM_SHA512").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (Hmac<Sha512>, Sha512, B1, Aes256Gcm)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_ChaChaPoly_SHA256() {
    let vector = TestVector::try_load("Noise_XK_25519_ChaChaPoly_SHA256").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (Hmac<Sha256>, Sha256, B0, ChaCha20Poly1305)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_AESGCM_SHA256() {
    let vector = TestVector::try_load("Noise_XK_25519_AESGCM_SHA256").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (Hmac<Sha256>, Sha256, B1, Aes256Gcm)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_ChaChaPoly_BLAKE2b() {
    let vector = TestVector::try_load("Noise_XK_25519_ChaChaPoly_BLAKE2b").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (SimpleHmac<Blake2b512>, Blake2b512, B0, ChaCha20Poly1305)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_AESGCM_BLAKE2b() {
    let vector = TestVector::try_load("Noise_XK_25519_AESGCM_BLAKE2b").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (SimpleHmac<Blake2b512>, Blake2b512, B1, aes_gcm::Aes256Gcm)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_ChaChaPoly_BLAKE2s() {
    let vector = TestVector::try_load("Noise_XK_25519_ChaChaPoly_BLAKE2s").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (SimpleHmac<Blake2s256>, Blake2s256, B0, ChaCha20Poly1305)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_25519_AESGCM_BLAKE2s() {
    let vector = TestVector::try_load("Noise_XK_25519_AESGCM_BLAKE2s").unwrap();
    xk::f::<C25519Scalar, [u8; 32], (SimpleHmac<Blake2s256>, Blake2s256, B1, aes_gcm::Aes256Gcm)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_ChaChaPoly_SHA512() {
    let vector = TestVector::try_load("Noise_XK_448_ChaChaPoly_SHA512").unwrap();
    xk::f::<X448Scalar, [u8; 56], (Hmac<Sha512>, Sha512, B0, ChaCha20Poly1305)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_AESGCM_SHA512() {
    let vector = TestVector::try_load("Noise_XK_448_AESGCM_SHA512").unwrap();
    xk::f::<X448Scalar, [u8; 56], (Hmac<Sha512>, Sha512, B1, Aes256Gcm)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_ChaChaPoly_SHA256() {
    let vector = TestVector::try_load("Noise_XK_448_ChaChaPoly_SHA256").unwrap();
    xk::f::<X448Scalar, [u8; 56], (Hmac<Sha256>, Sha256, B0, ChaCha20Poly1305)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_AESGCM_SHA256() {
    let vector = TestVector::try_load("Noise_XK_448_AESGCM_SHA256").unwrap();
    xk::f::<X448Scalar, [u8; 56], (Hmac<Sha256>, Sha256, B1, Aes256Gcm)>(&vector);
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_ChaChaPoly_BLAKE2b() {
    let vector = TestVector::try_load("Noise_XK_448_ChaChaPoly_BLAKE2b").unwrap();
    xk::f::<X448Scalar, [u8; 56], (SimpleHmac<Blake2b512>, Blake2b512, B0, ChaCha20Poly1305)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_AESGCM_BLAKE2b() {
    let vector = TestVector::try_load("Noise_XK_448_AESGCM_BLAKE2b").unwrap();
    xk::f::<X448Scalar, [u8; 56], (SimpleHmac<Blake2b512>, Blake2b512, B1, aes_gcm::Aes256Gcm)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_ChaChaPoly_BLAKE2s() {
    let vector = TestVector::try_load("Noise_XK_448_ChaChaPoly_BLAKE2s").unwrap();
    xk::f::<X448Scalar, [u8; 56], (SimpleHmac<Blake2s256>, Blake2s256, B0, ChaCha20Poly1305)>(
        &vector,
    );
}

#[test]
#[allow(non_snake_case)]
fn Noise_XK_448_AESGCM_BLAKE2s() {
    let vector = TestVector::try_load("Noise_XK_448_AESGCM_BLAKE2s").unwrap();
    xk::f::<X448Scalar, [u8; 56], (SimpleHmac<Blake2s256>, Blake2s256, B1, aes_gcm::Aes256Gcm)>(
        &vector,
    );
}
