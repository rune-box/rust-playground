use arrayref;
use bigint::U256;
use crypto::{digest::Digest, sha3::Sha3};
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

const PREFIX: &str = "\x19Ethereum Signed Message:\n";

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3::keccak256();
    hasher.input(data);

    let mut hash_data = [0; 32];
    hasher.result(&mut hash_data);
    hash_data
}

fn hash_message(msg: &str) -> [u8; 32] {
    let msg_bytes = msg.as_bytes();
    let mut eth_message = format!("{PREFIX}{}", msg_bytes.len()).into_bytes();
    eth_message.extend_from_slice(msg_bytes);

    let hash_data = keccak256(&eth_message);
    //println!("message hash: {}", hex::encode(hash_data));
    hash_data
}

fn process_signature_data(bytes: &[u8; 65]) -> (U256, U256, u64) {
    let v = bytes[64];
    let r = U256::from_big_endian(&bytes[0..32]);
    let s = U256::from_big_endian(&bytes[32..64]);
    let v64: u64 = v.into();
    (r, s, v64)
}

fn normalize_recovery_id(v: u64) -> u8 {
    match v {
        0 => 0,
        1 => 1,
        27 => 0,
        28 => 1,
        v if v >= 35 => ((v - 1) % 2) as _,
        _ => 4,
    }
}

fn ecrecover(msg_hash: [u8; 32], sig_hash: [u8; 65]) -> [u8; 20] {
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
    let hash = keccak256(&public_key[1..]);
    let r = arrayref::array_ref![hash, 12, 20];
    *r
}

fn ecrecover_hex(msg_hash: [u8; 32], sig_hash: [u8; 65], prefix_0x: bool) -> String {
    let bytes = ecrecover(msg_hash, sig_hash);
    match prefix_0x {
        true => format!("0x{}", hex::encode(bytes)),
        false => hex::encode(bytes),
    }
}

pub fn verify(account: &str, msg: &str, sig: &str) -> bool {
    let msg_bytes = hash_message(msg);
    let sig_bytes = hex::decode(sig).unwrap();
    let msg_data = arrayref::array_ref![msg_bytes, 0, 32];
    let sig_data = arrayref::array_ref![sig_bytes, 0, 65];

    let recovered_account = ecrecover_hex(*msg_data, *sig_data, true);
    //println!("ecrecover_hex: {}", recovered_account);
    recovered_account.eq_ignore_ascii_case(account)
}

//#[cfg(test)]
pub fn test_eth() {
    let account = "0x2bA1473Cb3973C288312a92FB8930bB0aF2cAe02";
    let msg = "hello, world!";
    let sig = "a9903a32e5ca4ba2ff89644d2f128a9ffa2ca4aec21c19932e04b4a050c317e176501e809e4367e05ba017b205df5c31cb4fa72df9b6d0e48b85796f6848472b1b";

    println!("account: {}", account);
    println!("message: {}", msg);
    println!("signature: {}", sig);

    let r = verify(account, msg, sig);
    println!("verify result: {}", r);
}
