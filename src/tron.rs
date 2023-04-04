use arrayref;
use hex;

const MAGIC_STR: &str = "\x19TRON Signed Message:\n";
//const ADDRESS_SIZE: i32 = 34;
const ADDRESS_PREFIX: &str = "41";
//const ADDRESS_PREFIX_BYTE: i32 = 0x41;

// Ref: https://github.com/tronprotocol/tronweb/blob/master/src/utils/crypto.js
fn get_base58_check_address(bytes: &[u8]) -> String {
    let hash0 = crate::utils::digest::sha256(bytes);
    let hash1 = crate::utils::digest::sha256(&hash0);
    
    let checksum = &hash1[0..4];
    let data_vec: Vec<u8> = bytes.iter().copied().chain(checksum.iter().copied()).collect();
    let base58 = bs58::encode(&data_vec).into_string();

    base58
}

// Ref: https://github.com/tronprotocol/tronweb/blob/master/src/utils/message.js
pub fn verify(account: &str, msg: &str, sig: &str) -> bool {
    let msg_bytes = crate::utils::digest::evm_hash_message(MAGIC_STR, msg);
    let sig_bytes = hex::decode(crate::utils::hex::try_remove_prefix(sig)).unwrap();
    let msg_data = arrayref::array_ref![msg_bytes, 0, 32];
    let sig_data = arrayref::array_ref![sig_bytes, 0, 65];

    let recovered_hex = crate::utils::evm::ecrecover_hex(*msg_data, *sig_data, false);
    let recovered_hex2 = format!("{ADDRESS_PREFIX}{recovered_hex}");
    let recovered_bytes = hex::decode(recovered_hex2).unwrap();
    let recovered_account = get_base58_check_address(&recovered_bytes);
    
    recovered_account.eq_ignore_ascii_case(account)
}

//#[cfg(test)]
pub fn test() {
    let account = "TEPwqbjym16qoy4gr3S7QwARBoxaBy8rbq";
    let msg = "hello, world!";
    let sig = "0x120c99e65e70dbbaa99f70e6cc61309c14be74d2f976628dacf758ccdb1702e43013716a26f4a266ab53bf8f8964da45529773fb53ce27947a09af430909ec7f1b";

    println!("account: {}", account);
    println!("message: {}", msg);
    println!("signature: {}", sig);

    let r = verify(account, msg, sig);
    println!("verify result: {}", r);
}
