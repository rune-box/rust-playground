use crypto::{digest::Digest};

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
