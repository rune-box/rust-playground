extern crate rsa;
use base64::{Engine as _, engine::general_purpose};
use elliptic_curve::pkcs8::{ DecodePublicKey};
use k256::sha2::Sha256;
//use crypto::{digest::Digest};
use rsa::{PublicKey, Pss};
extern crate jsonwebtoken as jwt;
extern crate jsonwebkey as jwk;

// pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
//     let mut hasher = crypto::sha2::Sha256::new();
//     hasher.input(data);
//     let mut sha256_data: [u8; 32] = [0; 32];
//     hasher.result(&mut sha256_data);

//     sha256_data
// }

pub fn get_address_from_public_key(data: &[u8]) -> String {
    let sha256_data = crate::utils::digest::sha256(data);
    //bufferTob64Url( hashData );
    let addr = general_purpose::URL_SAFE_NO_PAD.encode(sha256_data);
    
    addr
}

pub fn get_address_from_jwk_n(jwk_n: &str) -> String {
    // b64UrlToBuffer( n )
    let n_btyes = general_purpose::URL_SAFE_NO_PAD.decode(jwk_n).unwrap();
    get_address_from_public_key(&n_btyes)
}

pub fn verify(account: &str, public_key: &str, msg: &str, sig: &str) -> bool {
    let msg_bytes = msg.as_bytes();
    let sig_vec = general_purpose::STANDARD.decode(sig).unwrap();

    let pk_btyes = general_purpose::URL_SAFE_NO_PAD.decode(public_key).unwrap();
    let address = get_address_from_public_key(&pk_btyes);
    //println!("Computed address from jwk_n: {}", address); // ok
    let check_pk_account = address.eq_ignore_ascii_case(account);

    let jwt_str = format!("{{\"kty\": \"RSA\", \"n\": \"{}\", \"e\": \"AQAB\"}}", public_key);
    let the_jwk: jwk::JsonWebKey = jwt_str.parse().unwrap();
    let pem_str = the_jwk.key.to_pem();
    let rsa_pk = rsa::RsaPublicKey::from_public_key_pem(&pem_str).unwrap();
    
    let msg_hashed = crate::utils::digest::sha256(msg_bytes);
    let scheme = Pss::new::<Sha256>();
    let v = match rsa_pk.verify(scheme, &msg_hashed, &sig_vec) {
        Err(e) => {
            println!("Error: {}", e);
            false
        },
        Ok(()) => {
            check_pk_account
        }
    };

    v
}

//#[cfg(test)]
pub fn test_ar() {
    let account = "VZRK_MgvH9GWeV_tP3pVI8F22PuMFuA8bAHNCTpRsOI";
    let public_key = "rnPDOXWHmJ0E1PnSYIzlrm5V1P0Aw5CDD7J10PWCJuNFGMoeozqg515UEagYD1hQE3f9HhYOaLW1rsuQVP84_PM5enqIQjnxznRKI-EAOXt1OYtWnBSZhebwS30nvTAAdbnUFS7vXjnaeWC8QXPScxUCla1Ymu5g3-Akg9cMWm8KmPgKpks3pF5fZUAh--40gBoQlSzzKcMx9Fa4HJDsrprvA1PZaz0tvz6Dk2J9cxaf3MbVNRf2YsGCttKOnKxV-N-WGQVv0MXCu001qtiuK1gxnwAjk9goSsOCdD3ZcNJ3nz-NH95YrQ_GfJ0Igmy9BszDK2p26bOG8EzUZDvzMYYt3uRoL_NVRnNmfb2GZ_ViypBGrO69QXbE488namKybqomZJwuqIFATna7G4Q5ig3HJkIPJIVbmzGzeC67n_j4eYlJHzrb_dp2Bnq56i4zQGuw4jhuMGojDzlAeEJHg3WPAudhT_KWr9jak4_bdLAsLQy_9CLb9Td6sb-ZesLkSfCN3zc8204FjKjffy43vBn9mkLXI3-rrotIaaeEqlWDQ0iFxkYFPJIl_81WIU9uSYQnEvj5fdGI3JYOzRqhSuGvbskp1TKfzpfAwUMQ7tb4GP37g-eDLqh3dDW8hiv0mjJK5xvg0l9kv3NN1wfR3t-nBUYRl-Q81F3k16CFrks";
    let msg = "Hello, world!";
    let sig = "g0h896RT6CUOgg8ac903Xsfhks88YtatdQC6fD2hP+AVZBClvg3ahwB7q9tAkK9FP022JVhP3sMdHxKVTKvN50r1WXsPqq+avu8mEqjKp/FhNP77czJckJ6pRXpG0d2QVxuykNg2lx9gOUNLxMu1xBbb17lFf5opHabnaifZUvG/UC6WWyqYFCJiP/YDFnomGMBb/KOqcBmGX+1sePKKa1krsWtuCuFUCKHQaTEGHrj9elFErp9P8pTmWFUOE4L5DG+NZsh1jdXmpJIvm/4IwoWxdiv2mpnUXiCreUZ1xV51anzpOAQjsR4uEn19dSWsAG3DjBrO2d77IfvPH2zbGbitxmnHDVn5uH8KGhCkRUM597iamuvCe36eRD1Th2RS8E1J5JcXk5ummsWU3/uZA78taipMw11dzIxmSi2xo2WO0Nu59q22KzknCOJtZDVTyfLb3j1q0xFCAeoGflyazVJGKZKJ7AyrkyRkdmFbY+obsVoOL0ObmjqO355yP1JoQpXk/oM4A4Uzspqv/MbDyVWX+O+1DMvWnOyyjNkbAGJlFVWFt8BcZPnyHoKENWoZvMbzGGr3w3cuibdAoPGEqI8eOQgwADa8ocJkEqgesQuCC64K/UAt8YL2JFxQkzwQXdKCutakIfVd3CXWsLdsK5LxWIq87BwOWkk4mopkGhQ=";

    println!("account: {}", account);
    println!("public_key: {}", public_key);
    println!("message: {}", msg);
    println!("signature: {}", sig);

    let r = verify(account, public_key, msg, sig);
    println!("verify result: {}", r);
}