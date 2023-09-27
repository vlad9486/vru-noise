use core::ops::Mul;

pub trait EllipticSecret {
    type Public;

    fn from_bytes(bytes: &[u8]) -> Self;
    fn public(&self) -> Self::Public;
}

pub struct C25519Scalar(curve25519_dalek::scalar::Scalar);

pub struct C25519Point(curve25519_dalek::montgomery::MontgomeryPoint);

impl EllipticSecret for C25519Scalar {
    type Public = C25519Point;

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buffer = [0; 32];
        buffer.clone_from_slice(bytes);
        buffer[0] &= 248;
        buffer[31] &= 127;
        buffer[31] |= 64;

        let secret = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(buffer);
        C25519Scalar(secret)
    }

    fn public(&self) -> Self::Public {
        let t = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        let public = (t * &self.0).to_montgomery();
        C25519Point(public)
    }
}

impl AsRef<[u8; 32]> for C25519Point {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl<'a, 'b> Mul<&'b C25519Scalar> for &'a C25519Point {
    type Output = C25519Point;

    fn mul(self, rhs: &'b C25519Scalar) -> Self::Output {
        C25519Point(&self.0 * &rhs.0)
    }
}

pub struct X448Scalar(x448::Secret);

pub struct X448Point(x448::PublicKey);

impl EllipticSecret for X448Scalar {
    type Public = X448Point;

    fn from_bytes(bytes: &[u8]) -> Self {
        X448Scalar(x448::Secret::from_bytes(bytes).unwrap())
    }

    fn public(&self) -> Self::Public {
        X448Point(x448::PublicKey::from(&self.0))
    }
}

impl AsRef<[u8; 56]> for X448Point {
    fn as_ref(&self) -> &[u8; 56] {
        self.0.as_bytes()
    }
}

impl<'a, 'b> Mul<&'b X448Scalar> for &'a X448Point {
    type Output = X448Point;

    fn mul(self, rhs: &'b X448Scalar) -> Self::Output {
        X448Point(rhs.0.as_diffie_hellman(&self.0).unwrap())
    }
}
