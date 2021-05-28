#![allow(unused_imports)]

use halo2::{
    arithmetic::{Field, FieldExt},
    circuit::{layouter::SingleChipLayouter, Cell, Chip, Layouter},
    dev::{MockProver, VerifyFailure},
    pasta::Fp,
    plonk::{
        Advice, Assignment, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Permutation,
        Selector,
    },
    poly::Rotation,
};
use halo2_circuits::poseidon::{poseidon, HasherCircuit, N_ROWS_USED, PUB_INPUT_ROW_INDEX};
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

fn main() {
    // The public digest.
    let pub_input = Fp::from_bytes(&[
        92, 156, 142, 19, 149, 223, 255, 67, 5, 168,
        243, 206, 123, 14, 94, 31, 226, 187, 207, 47,
        97, 158, 70, 2, 132, 63, 106, 142, 219, 243,
        144, 17,
    ]).unwrap();

    // Verifier's public inputs.
    let k = (N_ROWS_USED as f32).log2().ceil() as u32;
    let n_rows = 1 << k;
    let mut pub_inputs = vec![Fp::zero(); n_rows];
    pub_inputs[PUB_INPUT_ROW_INDEX] = Fp::from(pub_input);

    // Prover's private inputs.
    let preimg = vec![Fp::from(55), Fp::from(101), Fp::from(237)];
    dbg!(poseidon(&preimg));
    // println!("{:?}", poseidon(&preimg).to_bytes());
    let circuit = HasherCircuit { preimg };

    let prover = MockProver::run(k, &circuit, vec![pub_inputs.clone()]).unwrap();
    // dbg!(prover.verify());
    assert!(prover.verify().is_ok());
}
