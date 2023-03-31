pub fn verify(account: &str, public_key: &str, msg: &str, sig: &str) -> bool {
    let pk_bytes = bs58::decode(public_key).into_vec().unwrap();
    let msg_bytes = msg.as_bytes();
    let sig_bytes = hex::decode(sig).unwrap();

    crypto::ed25519::verify(msg_bytes, &pk_bytes, &sig_bytes)
}

//#[cfg(test)]
pub fn test() {
    let account = "5rXWiaHfZjryPWsSM8PiKtaCzDWLcD1Y4kvfqRcZR7E8";
    let public_key = "5rXWiaHfZjryPWsSM8PiKtaCzDWLcD1Y4kvfqRcZR7E8";
    let msg = "Hello, world!";
    let sig: [u8; 64] = [
        253, 139, 145, 143, 41, 117, 42, 192, 35, 133, 60, 172, 51, 17, 217, 172, 144, 186, 89,
        157, 252, 220, 3, 60, 222, 76, 216, 249, 3, 144, 235, 31, 15, 168, 233, 110, 39, 122, 93,
        183, 55, 159, 251, 255, 22, 177, 74, 7, 18, 241, 156, 64, 229, 156, 76, 93, 16, 121, 232,
        109, 74, 168, 145, 8,
    ];
    let sig_hex = hex::encode(sig);

    println!("account: {}", account);
    println!("public_key: {}", public_key);
    println!("message: {}", msg);
    println!("signature: {}", sig_hex);

    let r = verify(account, public_key, msg, &sig_hex);
    println!("verify result: {}", r);
}