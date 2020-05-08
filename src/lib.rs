//! Rust AdMob SSV Validation
//!
//! This crate provides verification  a callback request (SSV) from AdMob. Please refer to the [documentation] for more information.
//!
//! It only does the verification process using openssl.
//!
//! It requires you to request the keys from the [AdMob key server]
//! insert them into a `Hashmap<u64, String>` and hand it over to the verifciation function.
//!
//! ### How to use
//!
//! This library only has one function `verify_ssv_callback`. It takes two parameters:
//!
//! `query_string: String`: The full query String including signature and key_id from the [callback]
//! `public_keys: Hashmap<u64, String>`: A HashMap of all public keys received from the [AdMob key server]
//!
//!
//! It returns either `Ok(bool)` if the verification was successful/unsuccessful or not or `Err(String)` when encountering an error during the whole validation process.
//!
//!
//! [documentation]: https://developers.google.com/admob/android/rewarded-video-ssv
//! [AdMob key server]: https://gstatic.com/admob/reward/verifier-keys.json
//! [callback]: https://developers.google.com/admob/android/rewarded-video-ssv#ssv_callback_parameters
//!
#![warn(missing_docs)]

use data_encoding::BASE64URL_NOPAD;
use openssl::nid::Nid;
use sha2::{Sha256, Digest};
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use std::collections::HashMap;

/// Does the verification of a AdMob SSV callback
pub fn verify_ssv_callback(query_string: &str, public_keys: &HashMap<u64, String>) -> Result<bool, String> {

    //find position in query_string where signature starts, fail otherwise
    let signature_position = match query_string.find("&signature") {
        None => { return Err(String::from("Could not find &signature= parameter in query_string")); }
        Some(x) => { x }
    };

    //message is query_string part until signature begins. this is the message that is later verified!
    let message = &query_string[..signature_position];
    //extract part from query_string where signature starts (including key_id parameter)
    let sig_and_key_id_part = String::from(&query_string[signature_position..]);
    //find position of key_id parameter, fail otherwise
    let key_id_position = match sig_and_key_id_part.find("&key_id") {
        None => { return Err(String::from("Could not find &key_id= parameter in query_string")); }
        Some(x) => { x }
    };
    //extract signature, this is later used to verify message against! remove leading 11 chars (&signature=)
    let signature = &sig_and_key_id_part[11..key_id_position];
    //find key_id part from signature_and_key_id string
    let key_id_part = String::from(&sig_and_key_id_part[key_id_position..]);
    //extract key_id (remove &key_id=). this is the public key_id from for the hashmap! parse as u64
    let key_id = match key_id_part[8..].parse::<u64>() {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not parse key_id as u64!")); }
    };

    //find the fitting Key in the HashMap of public keys. You should obtain those keys from https://www.gstatic.com/admob/reward/verifier-keys.json. See Readme
    let key = match public_keys.get(&key_id) {
        None => { return Err(String::from("Key not found!")); }
        Some(x) => { x }
    };

    //decode the base64 key as byte vector
    let mut octet_key = match base64::decode(key) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not decode base64 encoded Public key!")); }
    };
    //reverse the byte vector
    octet_key.reverse();
    //get 64 bytes (x and y points)
    octet_key.truncate(64);
    //reverse byte vector again to regain correct order
    octet_key.reverse();
    //split the byte vector in half to get both points
    let points = octet_key.split_at(32);
    //create points
    let x = match BigNum::from_slice(&points.0) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not convert the X coordinate of the public key to BigNum.")); }
    };
    let y = match BigNum::from_slice(&points.1) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not convert the Y coordinate of the public key to BigNum.")); }
    };
    //decode base64url signature as byte vector
    let signature_bytes = match BASE64URL_NOPAD.decode(signature.as_bytes()) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not decode the Base64Url encoded signature from the query_string")); }
    };
    //create ecdas signature from base64url decoded byte vector
    let ecdsa_signature = match EcdsaSig::from_der(&signature_bytes) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not decode the DER-encoded ECDSA signature.")); }
    };
    //create ecdsa curve group from secp256r1
    let group = match EcGroup::from_curve_name(Nid::X9_62_PRIME256V1) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not get the group of the X9_62_PRIME256V1 curve.")); }
    };
    //elliptic curve key from x and y coordinates from public key
    let ec_key = match EcKey::from_public_key_affine_coordinates(&*group, &*x, &*y) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not construct a public key from its affine coordinates.")); }
    };

    //convert url encoding to utf8 (%20, etc)
    let unquoted = match urlparse::unquote(message) {
        Ok(x) => { x }
        Err(_) => { return Err(String::from("Could not replace %xx escapes by their single-character equivalent.")); }
    };
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

