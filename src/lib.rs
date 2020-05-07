use data_encoding::BASE64URL_NOPAD;
use openssl::nid::Nid;
use sha2::{Sha256, Digest};
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ecdsa::EcdsaSig;
use std::collections::HashMap;

pub fn verify_ssv_callback(message: &str, key_id: &u64, signature: &str, public_keys: &HashMap<u64, String>) -> Result<bool, String> {
    //find the fitting Key in the HashMap of public keys. You should obtain those keys from https://www.gstatic.com/admob/reward/verifier-keys.json. See Readme
    let key = match public_keys.get(key_id) {
        None => { return Err(String::from("Key not found!")); }
        Some(x) => { x }
    };

    let mut octet_key = base64::decode(key).unwrap();
    octet_key.reverse();
    octet_key.truncate(64);
    octet_key.reverse();
    let points = octet_key.split_at(32);
    let x = BigNum::from_slice(&points.0).unwrap();
    let y = BigNum::from_slice(&points.1).unwrap();

    //decode base64url signature as byte vector
    let signature_bytes = BASE64URL_NOPAD.decode(signature.as_bytes()).unwrap();
    //create ecdas signature from base64url decoded byte vector
    let ecdsa_signature = EcdsaSig::from_der(&signature_bytes).unwrap();
    //create ecdsa curve group from secp256r1
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    //elliptic curve key from x and y coordinates from public key
    let ec_key = openssl::ec::EcKey::from_public_key_affine_coordinates(&*group, &*x, &*y).unwrap();

    //convert url encoding to utf8 (%20, etc)
    let unquoted = urlparse::unquote(message).unwrap();
    //hash the result as input for verification
    let mut hasher = Sha256::new();
    hasher.input(unquoted);
    let hashed_data = hasher.result().as_slice().to_owned();


    match ecdsa_signature.verify(&hashed_data, &*ec_key) {
        Ok(x) => { Ok(x) }
        Err(_) => { Err(String::from("Error verifying")) }
    }
}