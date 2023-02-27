use crypto::{digest::Digest};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input(data);
    let mut sha256_data: [u8; 32] = [0; 32];
    hasher.result(&mut sha256_data);

    sha256_data
}
