use rand::rngs::OsRng;
use trs::*;
use std::time::Instant;

// This function times the functions in lib.rs
fn main() {
    let start = Instant::now(); // start the timer
    println!("Timing TRS functions...");
    
    // 1. Key generation
    let ring_size = 3;
    let mut set_publickey = vec![[0u8; 32]; ring_size];
    let mut set_secretkey = vec![[0u8; 32]; ring_size];

    for i in 0..ring_size {
        let public_key = &mut set_publickey[i]; // &mut Vec<u8> of length 32
        let secret_key = &mut set_secretkey[i]; // &mut Vec<u8> of length 32

        trs_generate_keypair(secret_key, public_key);
    }

    // 2. Create a tag
    let issue = vec![0u8; 32]; // TODO(szhou): use Vec not vec! 
    let mut pubkeys = Vec::new();
    for i in 0..ring_size {
        let public_key= PublicKey::from_bytes(&set_publickey[i]).unwrap();
        pubkeys.push(public_key);
    }
    let tag = Tag{issue, pubkeys};
    println!("Tag generation done.");

    // 3. Sign, verify, and trace some messages
    let msg1 = vec![1u8; 32];
    let msg2 = vec![2u8; 32];
    let msg3 = vec![3u8; 32];

    // PrivateKey expects the scalar concatenated with the public key
    let secretkey = [&set_secretkey[0][..], &set_publickey[0][..]].concat();
    assert_eq!(secretkey.len(), 64);

    println!("======== Signing and verifying... ========");

    let mut R = OsRng;
    let sig1 = sign(&mut R, &msg1, &tag, &PrivateKey::from_bytes(&secretkey).unwrap());
    println!("Message 1 signed with secretkey 0.");
    println!("Verifying sig1 ...{}", verify(&msg1, &tag, &sig1));

    let sig2 = sign(&mut R, &msg2, &tag, &PrivateKey::from_bytes(&secretkey).unwrap());
    println!("Message 2 signed with secretkey 0.");
    println!("Verifying sig2 ...{}", verify(&msg2, &tag, &sig2));

    let sig3 = sign(&mut R, &msg1, &tag, &PrivateKey::from_bytes(&secretkey).unwrap());
    println!("Message 1 signed with secretkey 0.");
    println!("Verifying sig3 ...{}", verify(&msg1, &tag, &sig3));

    println!("======== Tracing... ========");

    println!("Tracing sig1 and sig2 ...{}", trace(&tag, &msg1, &msg2, &sig1, &sig2));
    println!("Tracing sig1 and sig3 ...{}", trace(&tag, &msg1, &msg1, &sig1, &sig3));

    let secretkey1 = [&set_secretkey[1][..], &set_publickey[1][..]].concat();
    assert_eq!(secretkey.len(), 64);

    println!("======== Signing and verifying... ========");

    let sig4 = sign(&mut R, &msg3, &tag, &PrivateKey::from_bytes(&secretkey1).unwrap());
    println!("Message 3 signed with secretkey 1.");
    println!("Verifying sig4 ...{}", verify(&msg3, &tag, &sig4));

    println!("======== Tracing... ========");

    println!("Tracing sig4 and sig1 ...{}", trace(&tag, &msg1, &msg3, &sig1, &sig4));
    println!("Tracing sig4 and sig2 ...{}", trace(&tag, &msg2, &msg3, &sig2, &sig4));
    println!("Tracing sig4 and sig3 ...{}", trace(&tag, &msg1, &msg3, &sig3, &sig4));

    let duration = start.elapsed(); // get elapsed time
    println!("Time elapsed: {:?}", duration);
}