use core::ops::Mul;

use alloc::vec::Vec;

use super::{test_vector::TestVector, elliptic::EllipticSecret};
use crate::{SymmetricState, ConfigExt, Output};

pub fn f<E, S, C>(v: &TestVector<'_>)
where
    C: ConfigExt,
    E: EllipticSecret,
    E::Public: AsRef<S>,
    S: AsRef<[u8]> + zeroize::Zeroize + Copy,
    for<'a, 'b> &'b E::Public: Mul<&'a E, Output = E::Public>,
{
    fn pair<E>(hex: &str) -> (E, E::Public)
    where
        E: EllipticSecret,
    {
        let secret = E::from_bytes(&hex::decode(hex).unwrap());
        let public = secret.public();
        (secret, public)
    }

    let init_ephemeral = pair::<E>(v.init_ephemeral);
    let resp_ephemeral = pair::<E>(v.resp_ephemeral.unwrap());
    let init_static = pair::<E>(v.init_static.unwrap());

    let mut payload0 = hex::decode(v.messages[0].payload).unwrap();
    let mut payload1 = hex::decode(v.messages[1].payload).unwrap();
    let mut init_static_compressed = init_static.1.as_ref().as_ref().to_vec();
    let mut payload2 = hex::decode(v.messages[2].payload).unwrap();
    let psk = hex::decode(v.psks[0]).unwrap();

    let Output {
        sender,
        receiver,
        hash,
    } = SymmetricState::<C, _>::new(v.name)
        .mix_hash(hex::decode(v.prologue).unwrap().as_slice())
        // -> e
        .mix_hash(init_ephemeral.1.as_ref().as_ref())
        .mix_shared_secret(*init_ephemeral.1.as_ref())
        .encrypt_ext(&mut payload0)
        // <- e, ee
        .mix_hash(resp_ephemeral.1.as_ref().as_ref())
        .mix_shared_secret(*resp_ephemeral.1.as_ref())
        .mix_shared_secret(*(&resp_ephemeral.1 * &init_ephemeral.0).as_ref())
        .encrypt_ext(&mut payload1)
        // -> s, se, psk
        .encrypt_ext(&mut init_static_compressed)
        .mix_shared_secret(*(&resp_ephemeral.1 * &init_static.0).as_ref())
        .mix_psk(psk)
        .encrypt_ext(&mut payload2)
        .finish::<1, true>();

    let mut ct = Vec::new();
    ct.extend_from_slice(init_ephemeral.1.as_ref().as_ref());
    ct.extend_from_slice(payload0.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[0].ciphertext, ct);

    let mut ct = Vec::new();
    ct.extend_from_slice(resp_ephemeral.1.as_ref().as_ref());
    ct.extend_from_slice(payload1.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[1].ciphertext, ct);

    let mut ct = Vec::new();
    ct.extend_from_slice(init_static_compressed.as_ref());
    ct.extend_from_slice(payload2.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[2].ciphertext, ct);

    assert_eq!(v.handshake_hash, hex::encode(hash));

    let _ = v.messages[3..]
        .iter()
        .fold((sender, receiver), |(mut sender, receiver), pair| {
            let mut buffer = hex::decode(pair.payload).unwrap();
            let tag = sender.encrypt(&[], buffer.as_mut());
            buffer.extend_from_slice(tag.as_ref());
            assert_eq!(pair.ciphertext, hex::encode(buffer));
            (receiver.swap(), sender.swap())
        });
}
