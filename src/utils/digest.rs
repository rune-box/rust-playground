use crypto::{digest::Digest};
use crypto::blake2b::Blake2b;

pub fn blake2b256(data: &[u8]) -> [u8; 64] {
    let out: &mut [u8; 64] = &mut [0; 64];
    //let blake = Blake2b::new(512);
    Blake2b::blake2b(out, &data, &[]);
    let r = arrayref::array_ref![out, 0, 64];
    *r
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = crypto::sha3::Sha3::keccak256();
    hasher.input(data);

    let mut hash_data = [0; 32];
    hasher.result(&mut hash_data);
    hash_data
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = crypto::ripemd160::Ripemd160::new();
    hasher.input(data);
    let mut ripemd160_data: [u8; 20] = [0; 20];
    hasher.result(&mut ripemd160_data);

    ripemd160_data
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input(data);
    let mut sha256_data: [u8; 32] = [0; 32];
    hasher.result(&mut sha256_data);

    sha256_data
}

pub fn evm_hash_message(magic_str: &str, msg: &str) -> [u8; 32] {
    let msg_bytes = msg.as_bytes();
    let mut evm_message = format!("{magic_str}{}", msg_bytes.len()).into_bytes();
    evm_message.extend_from_slice(msg_bytes);

    let hash_data = keccak256(&evm_message);
    hash_data
}
