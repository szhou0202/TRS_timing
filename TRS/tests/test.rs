use rand::rngs::OsRng;
use trs::*;
// use std::time::Instant;

#[test]
fn sum_to_n() {
    // Times the signing of messages, in other words, proof generation time 
    // a bunch of users sign the same message
    
    // generate n keys 
    let ring_size = 20;
    let mut set_publickey = vec![[0u8; 32]; ring_size];
    let mut set_secretkey = vec![[0u8; 32]; ring_size];

    for i in 0..ring_size {
        let public_key = &mut set_publickey[i]; // &mut Vec<u8> of length 32
        let secret_key = &mut set_secretkey[i]; // &mut Vec<u8> of length 32

        trs_generate_keypair(secret_key, public_key);
    }

    // create a tag
    let issue = vec![0u8; 32];
    let mut pubkeys = Vec::new();
    for i in 0..ring_size {
        let public_key= PublicKey::from_bytes(&set_publickey[i]).unwrap();
        pubkeys.push(public_key);
    }
    let tag = Tag{issue, pubkeys};

    // everyone signs the same message // TODO: message size also impacts this probably
    let msg = vec![1u8; 32];

    // PrivateKey expects the scalar concatenated with the public key
    let mut rng = OsRng; // what is R used for again

    for i in 0..ring_size {
        let secretkey = [&set_secretkey[i][..], &set_publickey[i][..]].concat();
        sign(&mut rng, &msg, &tag, &PrivateKey::from_bytes(&secretkey).unwrap());
    }

    // black_box(sum); // prevent compiler optimizations on unused variable
}