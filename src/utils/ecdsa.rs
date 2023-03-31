use bigint::U256;

// return (r, s, v)
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