use arrayref;
use bigint::U256;
// use crypto::{digest::Digest, sha3::Sha3};
use elliptic_curve::{consts::U32, sec1::ToEncodedPoint};
use generic_array::GenericArray;
use hex;
use k256::{
    ecdsa::{
        recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
        Signature as K256Signature,
    },
    PublicKey as K256PublicKey,
};

pub fn process_signature_data(bytes: &[u8; 65]) -> (U256, U256, u64) {
    let v = bytes[64];
    let r = U256::from_big_endian(&bytes[0..32]);
    let s = U256::from_big_endian(&bytes[32..64]);
    let v64: u64 = v.into();
    (r, s, v64)
}

pub fn normalize_recovery_id(v: u64) -> u8 {
    match v {
        0 => 0,
        1 => 1,
        27 => 0,
        28 => 1,
        v if v >= 35 => ((v - 1) % 2) as _,
        _ => 4,
    }
}

pub fn ecrecover(msg_hash: [u8; 32], sig_hash: [u8; 65]) -> [u8; 20] {
    let (r, s, v) = process_signature_data(&sig_hash);
    let recovery_id = RecoveryId::new(normalize_recovery_id(v)).unwrap();
    // get recovery signature
    let recoverable_sig = {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r.to_big_endian(&mut r_bytes);
        s.to_big_endian(&mut s_bytes);
        let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
        let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);
        let sig = K256Signature::from_scalars(*gar, *gas).unwrap();
        RecoverableSignature::new(&sig, recovery_id).unwrap()
    };
    let verify_key = recoverable_sig
        .recover_verifying_key_from_digest_bytes(msg_hash.as_ref().into())
        .unwrap();
    let public_key = K256PublicKey::from(&verify_key);
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = crate::utils::digest::keccak256(&public_key[1..]);
    let r = arrayref::array_ref![hash, 12, 20];
    *r
}

pub fn ecrecover_hex(msg_hash: [u8; 32], sig_hash: [u8; 65], prefix_0x: bool) -> String {
    let bytes = ecrecover(msg_hash, sig_hash);
    match prefix_0x {
        true => format!("0x{}", hex::encode(bytes)),
        false => hex::encode(bytes),
    }
}