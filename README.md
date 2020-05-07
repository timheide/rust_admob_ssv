Rust AdMob SSV Validation
=========================

This is a library for verifying a callback request (SSV) from AdMob. Please refer to the [official documentation](https://developers.google.com/admob/android/rewarded-video-ssv) for more information.

It only does the verification process using openssl.
It requires you to request the keys from the [AdMob key server](https://gstatic.com/admob/reward/verifier-keys.json) insert them into a Hashmap<u64, String> and hand it over to the verifciation function.

### How to use
This library only has one function `verify_ssv_callback`. It takes two parameters:

* query_string: The full query String including signature and key_id [Documentation](https://developers.google.com/admob/android/rewarded-video-ssv#ssv_callback_parameters)
* public_keys: A HashMap of all public keys received from the [AdMob key server](https://gstatic.com/admob/reward/verifier-keys.json)

