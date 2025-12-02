use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};//, black_box};
use trs::*;

fn proof_time_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_time");

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

fn trace_time_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_time");

    for &n in &RING_SIZES {
        let tup = generate_keys_and_message(n);
        let set_publickey = tup.0;
        let set_secretkey = tup.1;
        let tag = tup.2;
        let msg = tup.3;

        let sigs = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());
        let sigs2 = proof_time(n, set_publickey.clone(), set_secretkey.clone(), tag.clone(), msg.clone());

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| trace_time(msg.clone(), msg.clone(), tag.clone(), sigs[0].clone(), sigs2[0].clone()))
        });
    }

    group.finish();
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

criterion_group!(benches, trace_time_bench);
criterion_main!(benches);
