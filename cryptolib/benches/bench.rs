use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};//, black_box};
use trs::*;
use rand::rngs::OsRng;

const RING_SIZES: [usize; 7] = [16, 32, 64, 128, 256, 512, 1024];

fn generate_keys_and_message(ring_size: usize) -> (Vec<[u8;32]>, Vec<[u8;32]>, Tag, Vec<u8>){
    // generate n keys 
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
    (set_publickey, set_secretkey, tag, msg)
}

fn proof_time(ring_size: usize, set_publickey: Vec<[u8;32]>, set_secretkey: Vec<[u8;32]>, tag: Tag, msg: Vec<u8>) -> Vec<Signature> {
    // Times the signing of messages, in other words, proof generation time 
    // a bunch of users sign the same message

    // PrivateKey expects the scalar concatenated with the public key
    let mut rng = OsRng; // what is R used for again

    let mut sigs = Vec::new();
    // for i in 0..ring_size {
    let secretkey = [&set_secretkey[0][..], &set_publickey[0][..]].concat();
    sigs.push(sign(&mut rng, &msg, &tag, &PrivateKey::from_bytes(&secretkey).unwrap()));
    // }
    sigs
}

fn proof_time_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_time");

    // this code is super slow T-T
    // indicates that it is not linear in this time
    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone()))
        });
    }

    group.finish();
}

fn verification_time(msg: Vec<u8>, tag: Tag, sigs: Vec<Signature>, ring_size: usize) {
    // Times the verification of messages, in other words, proof verification time 
    // a bunch of users sign the same message
    // for i in 0..ring_size {
    verify(&msg, &tag, &sigs[0]);
    // }
}

fn verification_time_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_time");

    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;

        let sigs = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| verification_time(msg.clone(), tag.clone(), sigs.clone(), n))
        });
    }

    group.finish();
}

fn generation_time(ring_size: usize) {
    // Times the keys and tag generation time
    
    // generate n keys 
    generate_keys_and_message(ring_size);
}

fn generation_time_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("generation_time");

    for &n in &RING_SIZES {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| generation_time(n))
        });
    }

    group.finish();
}

criterion_group!(benches, generation_time_bench, proof_time_bench, verification_time_bench);
criterion_main!(benches);
