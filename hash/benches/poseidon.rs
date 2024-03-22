use criterion::{criterion_group, criterion_main, Criterion};

use ark_bn254::Fr;
use ark_ff::Zero;
use shitty_hash::poseidon::{Poseidon, PoseidonHashType};

fn criterion_benchmark(c: &mut Criterion) {
    let state: Vec<Fr> = vec![Fr::from(1), Fr::from(2)];
    let mut pos = Poseidon::new(state, PoseidonHashType::ConstInputLen);

    c.bench_function("hash", |b| b.iter(|| pos.hash().unwrap_or(Fr::zero())));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
