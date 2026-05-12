// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use dusk_curves::bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar, msm_variable_base,
    multi_miller_loop_result, pairing_product_is_identity, scalar_from_wide,
};

const MSM_SIZES: &[usize] = &[1, 8, 64, 256];
const PAIRING_SIZES: &[usize] = &[1, 2, 4, 8];

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn wide_bytes(domain: u64, index: usize) -> [u8; 64] {
    let mut state = domain ^ (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let mut bytes = [0u8; 64];

    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }

    bytes
}

fn scalar_at(domain: u64, index: usize) -> Scalar {
    scalar_from_wide(&wide_bytes(domain, index))
}

fn scalars(count: usize) -> Vec<Scalar> {
    (0..count)
        .map(|index| scalar_at(0x5343_414c_4152_535f, index))
        .collect()
}

fn g1_points(count: usize) -> Vec<G1Affine> {
    (0..count)
        .map(|index| {
            let scalar = scalar_at(0x4731_5f50_4f49_4e54, index);
            G1Affine::from(G1Projective::generator() * scalar)
        })
        .collect()
}

fn g2_points(count: usize) -> Vec<G2Affine> {
    (0..count)
        .map(|index| {
            let scalar = scalar_at(0x4732_5f50_4f49_4e54, index);
            G2Affine::from(G2Projective::generator() * scalar)
        })
        .collect()
}

fn bench_msm_variable_base(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("bls12_381/msm_variable_base");
    group.sample_size(10);

    for &size in MSM_SIZES {
        let points = g1_points(size);
        let scalars = scalars(size);

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bencher, _| {
            bencher.iter(|| {
                msm_variable_base(black_box(points.as_slice()), black_box(scalars.as_slice()))
            })
        });
    }

    group.finish();
}

fn bench_multi_miller_loop_result(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("bls12_381/multi_miller_loop_result");
    group.sample_size(10);

    for &size in PAIRING_SIZES {
        let g1_points = g1_points(size);
        let g2_points = g2_points(size);
        let prepared: Vec<_> = g2_points.iter().copied().map(G2Prepared::from).collect();
        let terms: Vec<_> = g1_points.iter().zip(prepared.iter()).collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bencher, _| {
            bencher.iter(|| multi_miller_loop_result(black_box(terms.as_slice())))
        });
    }

    group.finish();
}

fn bench_pairing_product_is_identity(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("bls12_381/pairing_product_is_identity");
    group.sample_size(10);

    for &size in PAIRING_SIZES {
        let g1_points = g1_points(size);
        let g2_points = g2_points(size);
        let terms: Vec<_> = g1_points.iter().zip(g2_points.iter()).collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bencher, _| {
            bencher.iter(|| pairing_product_is_identity(black_box(terms.as_slice())))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_msm_variable_base,
    bench_multi_miller_loop_result,
    bench_pairing_product_is_identity
);
criterion_main!(benches);
