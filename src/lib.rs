#![allow(unused_imports)]

pub mod merkle;
pub mod poseidon;

use halo2::{circuit::Cell, pasta::Fp};

pub use crate::merkle::{MerkleChip, MerkleCircuit};
pub use crate::poseidon::{PoseidonChip, HasherCircuit};

#[derive(Clone, Debug)]
pub struct Alloc {
    cell: Cell,
    value: Fp,
}

#[derive(Clone, Debug)]
pub enum MaybeAlloc {
    Allocated(Alloc),
    Unallocated(Fp),
}

impl MaybeAlloc {
    pub fn value(&self) -> Fp {
        match self {
            MaybeAlloc::Allocated(alloc) => alloc.value.clone(),
            MaybeAlloc::Unallocated(value) => value.clone(),
        }
    }

    pub fn cell(&self) -> Cell {
        match self {
            MaybeAlloc::Allocated(alloc) => alloc.cell.clone(),
            MaybeAlloc::Unallocated(_) =>
                panic!("called `MaybeAlloc::cell()` on an unallocated value"),
        }
    }
}
