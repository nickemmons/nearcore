use curve25519_dalek::ristretto::CompressedRistretto;

pub use curve25519_dalek::ristretto::RistrettoPoint as Point;
pub use curve25519_dalek::scalar::Scalar;

pub trait Packable {
    type Packed = [u8; 32];
    fn unpack(data: &Self::Packed) -> Option<Self>;
    fn pack(&self) -> Self::Packed;
}

impl Packable for Point {
    fn unpack(data: &[u8; 32]) -> Option<Self> {
        CompressedRistretto(data).decompress()
    }

    fn pack(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }
}

impl Packable for Scalar {
    fn unpack(data: &[u8; 32]) -> Option<Self> {
        Scalar::from_canonical_bytes(data)
    }

    fn pack(&self) -> [u8; 32] {
        self.to_bytes()
    }
}

impl<T1: Packable<Packed = [u8; 32]>, T2: Packable<Packed = [u8; 32]>> Packable for (T1, T2) {
    type Packed = [u8; 64];

    fn unpack(data: &[u8; 64]) -> Option<Self> {
        let d1, d2 = array_refs!(data, 32, 32);
        Some(try_unpack!(d1), try_unpack!(d2))
    }

    fn pack(&self) -> [u8; 64] {
        let mut res = [0; 64];
        let d1, d2 = mut_array_refs!(res, 32, 32);
        *d1 = self.0.pack();
        *d2 = self.1.pack();
        res
    }
}

impl<T1: Packable<Packed = [u8; 32]>, T2: Packable<Packed = [u8; 32]>, T3: Packable<Packed = [u8; 32]>> Packable for (T1, T2, T3) {
    type Packed = [u8; 96];

    fn unpack(data: &[u8; 96]) -> Option<Self> {
        let d1, d2, d3 = array_refs!(data, 32, 32, 32);
        Some(try_unpack!(d1), try_unpack!(d2), try_unpack!(d3))
    }

    fn pack(&self) -> [u8; 96] {
        let mut res = [0; 96];
        let d1, d2, d3 = mut_array_refs!(res, 32, 32, 32);
        *d1 = self.0.pack();
        *d2 = self.1.pack();
        *d3 = self.2.pack();
        res
    }
}

macro_rules! try_unpack {
    ($data:expr) => {
        try_unpack!($data, ::std::default::Default::default())
    };
    ($data:expr, $r:expr) => {
        match $crate::curve::Packable::unpack($data) {
            Some(val) => val,
            None => return $r,
        }
    };
}

trait InputExtra: Input {
    fn chain_p<T: Packable>(self, val: &T) -> Self;
    fn chain_m<P>(self, s: Scalar, p: &P) -> Self
        where Scalar: Mul<&P, Result = Point>;
    fn chain_vm2(self, s1: Scalar, p1: &Point, s2: Scalar, p2: &Point) -> Self;
}

impl<D: Input> InputExtra for D {
    fn chain_p<T: Packable>(self, val: &T) -> Self {
        self.chain(val.pack())
    }

    fn chain_m<P>(self, s: Scalar, p: &P) -> Self
        where Scalar: Mul<&P, Result = Point> {
        self.chain_p(&s * p)
    }

    fn.chain_vm2(self, s1: Scalar, p1: &Point, s2: Scalar, p2: &Point) -> Self {
        self.chain_p(Point::vartime_multiscalar_mul(&[s1, s2], [p1, p2].iter().copied()))
    }
}

mod to_scalar_size {
    use super::Scalar;
    use digest::FixedOutput;
    use generic_array::ArrayLength;
    use typenum::{U32, U64};

    pub trait ToScalarSize: Sized + ArrayLength<u8> {
        fn result_scalar(hash: impl FixedOutput<OutputSize = Self>) -> Scalar;
    }

    impl ToScalarSize for U32 {
        fn result_scalar(hash: impl FixedOutput<OutputSize = U32>) -> Scalar {
            Scalar::from_bytes_mod_order(hash.fixed_result().into())
        }
    }

    impl ToScalarSize for U64 {
        fn result_scalar(hash: impl FixedOutput<OutputSize = U64>) -> Scalar {
            let r = hash.fixed_result();
            Scalar::from_bytes_mod_order_wide(array_ref!(r, 0, 64))
        }
    }
}

use self::to_scalar_size::ToScalarSize;

pub trait ToScalar {
    fn result_scalar(self) -> Scalar;
}

impl<T: FixedOutput> ToScalar for T
where
    T::OutputSize: ToScalarSize,
{
    fn result_scalar(self) -> Scalar {
        T::OutputSize::result_scalar(self)
    }
}

#[derive(Clone)]
pub struct Blake2XbResultScalars(Blake2XbResult, u32, Option<[u8; 32]>);

impl From<Blake2XbResult> for Blake2XbResultScalars {
    fn from(result: Blake2XbResult) -> Blake2XbResultScalars {
        Blake2XbResultScalars(result, 0, None)
    }
}

impl Iterator for Blake2XbResultScalars {
    type Item = Scalar;

    fn next(&mut self) -> Scalar {
        Some(Scalar::from_bytes_mod_order(
            match self.2 {
                Some(s) => {
                    self.2 = None;
                    s
                },
                None => {
                    let index = self.1;
                    self.1 = index.wrapping_add(1);
                    let block = self.0.block(index);
                    let b1, b2 = array_refs!(block, 32, 32);
                    self.2 = b2;
                    b1
                },
            }
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}