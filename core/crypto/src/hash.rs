use blake2::VarBlake2b;
use generic_array::GenericArray;
use digest::{BlockInput, FixedOutput, Input, Reset, VariableOutput};

pub use blake2::Blake2b as Hash512;

#[derive(Clone)]
pub struct Hash256(VarBlake2b);

impl Default for Hash256 {
    fn default() -> Self {
        Hash256(VarBlake2b::new(32).unwrap())
    }
}

impl Input for Hash256 {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.input(data);
    }
}

impl BlockInput for Hash256 {
    type BlockSize = VarBlake2b::BlockSize;
}

impl FixedOutput for Hash256 {
    type OutputSize = U32;

    fn fixed_result(self) -> GenericArray<u8, U32> {
        let mut r = [0; 32];
        self.0.variable_result(|s| {
            r = *array_ref!(s, 0, 32);
        });
        r.into()
    }
}

impl Reset for Hash256 {
    fn reset(&mut self) {
        self.0.reset();
    }
}

macro_rules! hasher {
    ($h:ty, $($d:expr,)* $dl:expr) => {
        hasher!($h $(, $d)*).chain($dl)
    };
    ($h:ty) => {
        $h::default()
    };
}

macro_rules! hash {
    ($($d:expr),*) => {
        hasher!(Hash256 $(, $d)*)
    };
}

macro_rules! prs {
    ($($d:expr),*) => {
        hasher!(Hash512 $(, $d)*).result_scalar()
    };
}

pub struct Blake2Xb(Blake2b512); // TODO
pub struct Blake2XbResult(Blake2b512); // TODO

impl Blake2Xb {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub fn with_output_size(output_size: u32) -> Self {
        unimplemented!()
    }

    pub fn result(self) -> Blake2XbResult {
        unimplemented!()
    }
}

impl Input for Blake2Xb {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        unimplemented!()
    }
}

impl Blake2XbResult {
    pub const BLOCK_SIZE: usize = 64;

    pub fn block(index: u32) -> [u8; 64] {
        unimplemented!()
    }

    pub fn range(offset: u64, dest: &mut impl BorrowMut<[u8]>) {
        unimplemented!()
    }
}