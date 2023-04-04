use arrayref;
use hex;

const MAGIC_STR: &str = "\x19Ethereum Signed Message:\n";


pub fn verify(account: &str, msg: &str, sig: &str) -> bool {
    let msg_bytes = crate::utils::digest::evm_hash_message(MAGIC_STR, msg);
    let sig_bytes = hex::decode(crate::utils::hex::try_remove_prefix(sig)).unwrap();
    let msg_data = arrayref::array_ref![msg_bytes, 0, 32];
    let sig_data = arrayref::array_ref![sig_bytes, 0, 65];

    let recovered_account = crate::utils::evm::ecrecover_hex(*msg_data, *sig_data, true);

    recovered_account.eq_ignore_ascii_case(account)
}

//#[cfg(test)]
pub fn test() {
    let account = "0x2bA1473Cb3973C288312a92FB8930bB0aF2cAe02";
    let msg = "hello, world!";
    let sig = "a9903a32e5ca4ba2ff89644d2f128a9ffa2ca4aec21c19932e04b4a050c317e176501e809e4367e05ba017b205df5c31cb4fa72df9b6d0e48b85796f6848472b1b";

    println!("account: {}", account);
    println!("message: {}", msg);
    println!("signature: {}", sig);

    let r = verify(account, msg, sig);
    println!("verify result: {}", r);
}
