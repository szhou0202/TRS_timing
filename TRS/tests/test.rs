use rand::rngs::OsRng;
use trs::*;
use std::time::Instant;

#[test]
fn strawman() {
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

pub fn proof_time(ring_size: usize, set_publickey: Vec<[u8;32]>, set_secretkey: Vec<[u8;32]>, tag: Tag, msg: Vec<u8>) -> Vec<Signature> {
    // Times the signing of messages, in other words, proof generation time 

    // PrivateKey expects the scalar concatenated with the public key
    let mut rng = rand::thread_rng(); // szhou: what is this used for again???

    let mut sigs = Vec::new();
    // for i in 0..ring_size {
    let secretkey = [&set_secretkey[0][..], &set_publickey[0][..]].concat();
    // sign(&mut rng, &msg, &tag, &PrivateKey::from_bytes(&secretkey).unwrap())
    sigs.push(sign(&mut rng, &msg, &tag, &PrivateKey::from_bytes(&secretkey).unwrap()));
    // }
    sigs
}

#[test]
fn proof_time_bench() {
    println!("proof time");
    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;
        
        let trials = 10;
        let mut times: Vec<f64> = Vec::with_capacity(trials);

        for _ in 0..trials {
            let start = Instant::now();
            let _ = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());
            let elapsed = start.elapsed();
            times.push(elapsed.as_millis() as f64);
        }

        let mean: f64 = times.iter().sum::<f64>() / trials as f64;
        let variance: f64 = times
            .iter()
            .map(|t| (t - mean).powi(2))
            .sum::<f64>()
            / (trials-1) as f64;

        let std_dev: f64 = variance.sqrt();

        println!("n: {}, ms: {}+{:.3}", n, mean, std_dev);
    }
}

pub fn verification_time(msg: Vec<u8>, tag: Tag, sigs: Vec<Signature>, ring_size: usize) {
    // Times the verification of messages, in other words, proof verification time 
    // a bunch of users sign the same message
    // for i in 0..ring_size {
    verify(&msg, &tag, &sigs[0]);
    // }
}

#[test]

fn verification_time_bench() {
    println!("verify time");
    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;

        let sigs = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());

        let trials = 10;
        let mut times: Vec<f64> = Vec::with_capacity(trials);

        for _ in 0..trials {
            let start = Instant::now();
            verification_time(msg.clone(), tag.clone(), sigs.clone(), n);
            let elapsed = start.elapsed();
            times.push(elapsed.as_millis() as f64);
        }

        let mean: f64 = times.iter().sum::<f64>() / trials as f64;
        let variance: f64 = times
            .iter()
            .map(|t| (t - mean).powi(2))
            .sum::<f64>()
            / (trials-1) as f64;

        let std_dev: f64 = variance.sqrt();

        println!("n: {}, ms: {}+{:.3}", n, mean, std_dev);
    }
}

pub fn trace_time(msg1: Vec<u8>, msg2: Vec<u8>, tag: Tag, sig1: Signature, sig2: Signature) {
    trace(&tag, &msg1, &msg2, &sig1, &sig2);
}

#[test]
fn trace_time_bench() {
    println!("trace time");
    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;

        let sigs = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());
        let sigs2 = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());

        let trials = 10;
        let mut times: Vec<f64> = Vec::with_capacity(trials);

        for _ in 0..trials {
            let start = Instant::now();
            trace_time(msg.clone(), msg.clone(), tag.clone(), sigs[0].clone(), sigs2[0].clone());
            let elapsed = start.elapsed();
            times.push(elapsed.as_millis() as f64);
        }

        let mean: f64 = times.iter().sum::<f64>() / trials as f64;
        let variance: f64 = times
            .iter()
            .map(|t| (t - mean).powi(2))
            .sum::<f64>()
            / (trials-1) as f64;

        let std_dev: f64 = variance.sqrt();

        println!("n: {}, ms: {}+{:.3}", n, mean, std_dev);
    }
}