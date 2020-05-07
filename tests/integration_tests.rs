use rust_admob_ssv::verify_ssv_callback;
use std::collections::HashMap;

#[test]
fn successful_verification_with_minimum_parameters() {
    let mut hashmap : HashMap<u64, String> = HashMap::new();
    hashmap.insert(3335741209, String::from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+nzvoGqvDeB9+SzE6igTl7TyK4JBbglwir9oTcQta8NuG26ZpZFxt+F2NDk7asTE6/2Yc8i1ATcGIqtuS5hv0Q=="));
    let callback = verify_ssv_callback("ad_network=5450213213286189855&ad_unit=1234567890&timestamp=1588756506292&transaction_id=123456789&signature=MEQCIA54vhOTh9NjebJJZM6Pvgcz1UMd6Jn3G6WQ8czPoEPdAiBwXX1aOG4Cz219vH_VPXicw5K9w8XqOmWHYmQgKtJmsA&key_id=3335741209", &hashmap);
    assert!(callback.unwrap());
}

#[test]
fn successful_verification_with_all_parameters() {
    let mut hashmap : HashMap<u64, String> = HashMap::new();
    hashmap.insert(3335741209, String::from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+nzvoGqvDeB9+SzE6igTl7TyK4JBbglwir9oTcQta8NuG26ZpZFxt+F2NDk7asTE6/2Yc8i1ATcGIqtuS5hv0Q=="));
    let callback = verify_ssv_callback("ad_network=5450213213286189855&ad_unit=1234567890&custom_data=a&timestamp=1588787075450&transaction_id=123456789&user_id=1&signature=MEUCIA7MmmfAIvIq78myiVZ_cf4ykFAKOXt_JXGbN6LqGRUPAiEAw0SbAWnx1qR34M_A0QYVd5Pc22XoFzHq8EcICZoOYzs&key_id=3335741209", &hashmap);
    assert!(callback.unwrap());
}

#[test]
fn successful_verification_with_all_parameters_and_encoded_spaces() {
    let mut hashmap : HashMap<u64, String> = HashMap::new();
    hashmap.insert(3335741209, String::from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+nzvoGqvDeB9+SzE6igTl7TyK4JBbglwir9oTcQta8NuG26ZpZFxt+F2NDk7asTE6/2Yc8i1ATcGIqtuS5hv0Q=="));
    let callback = verify_ssv_callback("ad_network=5450213213286189855&ad_unit=1234567890&custom_data=test%20with%20spaces&timestamp=1588893178205&transaction_id=123456789&user_id=user1234&signature=MEYCIQCgskFKBxxLi3ae8lDThSLf8ZFnu4aiAEsEpbrpVZcCkAIhAJ9p_wYfR8I6EU1iiLzD9q_Tm8263IeVdW-ODIigfD2V&key_id=3335741209", &hashmap);
    assert!(callback.unwrap());
}

