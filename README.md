Rust AdMob SSV Validator
========================

This is a library for verifying a callback request (SSV) from AdMob. Please refer to the [official documentation](https://developers.google.com/admob/android/rewarded-video-ssv) for more information.

It only does the verification process using openssl and doesn't receive the keys from the AdMob key servers. 
It also requires you to prepare the parameters yourself beforehand.

### How to use
This library only has one function `verify_ssv_callback`. It takes four parameters:

* message: The message part of the GET-Request that the signature is verified against. [Documentation](https://developers.google.com/admob/android/rewarded-video-ssv#get_content_to_be_verified)
* key_id: The id of the public key that fits the signature. It's the last part of the callback request [Dodcumentation](https://developers.google.com/admob/android/rewarded-video-ssv#get_signature_and_key_id_from_callback_url)
* signature: The Signature. It's the second last parameter of the callback request [Dodcumentation](https://developers.google.com/admob/android/rewarded-video-ssv#get_signature_and_key_id_from_callback_url)
* public_keys: A HashMap of all public keys received from the [AdMob key server](https://gstatic.com/admob/reward/verifier-keys.json)

