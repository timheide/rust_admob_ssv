use data_encoding::BASE64URL_NOPAD;
use openssl::nid::Nid;
use sha2::{Sha256, Digest};
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ecdsa::EcdsaSig;
use std::collections::HashMap;

pub fn verify_ssv_callback(query_string: &str, public_keys: &HashMap<u64, String>) -> Result<bool, String> {

    //extract parts from full query string
    let signature_position = query_string.find("&signature").unwrap();
    let message = &query_string[..signature_position];
    let sig_and_key_id_part =  String::from(&query_string[signature_position..]);
    let key_id_position = sig_and_key_id_part.find("&key_id").unwrap();
    let signature = &sig_and_key_id_part[11..key_id_position];
    let key_id_part =  String::from(&sig_and_key_id_part[key_id_position..]);
    let key_id = &key_id_part[8..].parse::<u64>().unwrap();

    //find the fitting Key in the HashMap of public keys. You should obtain those keys from https://www.gstatic.com/admob/reward/verifier-keys.json. See Readme
    let key = match public_keys.get(key_id) {
        None => { return Err(String::from("Key not found!")); }
        Some(x) => { x }
    };

    //decode the base64 key as byte vector
    let mut octet_key = base64::decode(key).unwrap();
    //reverse the byte vector
    octet_key.reverse();
    //get 64 bytes (x and y points)
    octet_key.truncate(64);
    //reverse byte vector again to regain correct order
    octet_key.reverse();
    //split the byte vector in half to get both points
    let points = octet_key.split_at(32);
    //create points
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

    //verify signature
    match ecdsa_signature.verify(&hashed_data, &*ec_key) {
        Ok(x) => { Ok(x) }
        Err(_) => { Err(String::from("Error verifying")) }
    }
}

