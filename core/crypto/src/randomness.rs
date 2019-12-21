use crate::curve::*;
use crate::hash::Hash512;
use c2_chacha::guts::ChaCha;
use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE as GT,
};
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use std::borrow::Borrow;
use std::convert::TryInto;
use std::iter::once;
use std::ops::{Add, Deref, DerefMut, Sub};

pub use crate::vrf::{PublicKey, SecretKey};

#[derive(Clone)]
struct ChaChaScalars(ChaCha, Option<[u8; 32]>);

impl ChaChaScalars {
    fn from_hash(hash: [u8; 32]) -> Self {
        ChaChaScalars(ChaCha::new(&hash, &[0; 8]), None)
    }
}

impl Iterator for ChaChaScalars {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        Some(Scalar::from_bytes_mod_order(match self.1 {
            Some(s) => {
                self.1 = None;
                s
            }
            None => {
                let mut block = [0; 64];
                self.0.refill(6, &mut block);
                let (b1, b2) = array_refs!(&block, 32, 32);
                self.1 = Some(*b2);
                *b1
            }
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

struct ExpandIter<T>(Box<[T]>);

fn expand<T: Copy, E: Iterator>(els: E) -> ExpandIter<T>
where
    E::Item: Borrow<T>,
    for<'a> &'a T: Sub<Output = T>,
{
    let mut res = Vec::with_capacity(els.size_hint().0);
    for vv in els {
        let mut v = *vv.borrow();
        for v2 in res.iter_mut() {
            let dif = &v - v2;
            *v2 = v;
            v = dif;
        }
        res.push(v);
    }
    ExpandIter(res.into_boxed_slice())
}

impl<T: Copy + Default + 'static> Iterator for ExpandIter<T>
where
    for<'a> &'a T: Add<Output = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<T> {
        Some(if self.0.is_empty() {
            T::default()
        } else {
            let mut v = self.0[self.0.len() - 1];
            let r = 0..self.0.len() - 1;
            for v2 in self.0[r].iter_mut().rev() {
                v = &*v2 + &v;
                *v2 = v;
            }
            v
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicShare(pub Box<[u8]>);
#[derive(Clone, PartialEq, Eq)]
pub struct SecretShare(Box<[Scalar]>);
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedPublicShare(Box<[Point]>);

pub fn generate_share(
    key: &PublicKey,
    n: u32,
    k: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (PublicShare, SecretShare) {
    assert!(k <= n && n < u32::max_value() / 32); // XXX
    let mut public = Vec::with_capacity(
        TryInto::<usize>::try_into(k).unwrap().checked_mul(32).unwrap().checked_add(64).unwrap(),
    );
    let mut secret = Vec::with_capacity(n.try_into().unwrap());
    for _ in 0..k {
        let s = Scalar::random(rng);
        public.extend_from_slice(&(&s * &GT).pack());
        secret.push(s);
    }
    let mut r = Scalar::random(rng);
    public.extend_from_slice(&(&r * &GT).pack());
    secret.iter().zip(ChaChaScalars::from_hash(hash!(key, &public))).for_each(|(s, c)| r -= c * s);
    public.extend_from_slice(&r.pack());
    secret.extend(expand::<Scalar, _>(secret.iter()).take((n - k) as usize));
    debug_assert!(public.len() == (k as usize) * 32 + 64 && secret.len() == n as usize);
    (PublicShare(public.into_boxed_slice()), SecretShare(secret.into_boxed_slice()))
}

impl PublicShare {
    pub fn validate(&self, key: &PublicKey) -> Option<ValidatedPublicShare> {
        assert!(self.0.len() >= 64 && self.0.len() % 32 == 0);
        let k: u32 = ((self.0.len() - 64) / 32).try_into().unwrap(); // XXX usize
        assert!(k < u32::max_value() / 32);
        let mut res = Vec::with_capacity(k as usize);
        for i in 0..k as usize {
            res.push(try_unpack!(array_ref!(self.0, 32 * i, 32), None));
        }
        let comm = array_ref!(self.0, 32 * k as usize, 32);
        let r = try_unpack!(array_ref!(self.0, 32 * k as usize + 32, 32), None);
        if Point::vartime_multiscalar_mul(
            ChaChaScalars::from_hash(hash!(key, &self.0[..32 * (k as usize) + 32])).chain(once(r)),
            res.iter().chain(once(&G)),
        )
        .pack()
            != *comm
        {
            return None;
        }
        Some(ValidatedPublicShare(res.into_boxed_slice()))
    }
}

value_type!(pub, EncryptedShare, 32, "encrypted share");
#[derive(Copy, Clone)]
pub struct DecryptedShare(Scalar);
value_type!(pub, DecryptionFailureProof, 96, "decryption failure proof");

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut res = [0; 32];
    for i in 0..32 {
        res[i] = a[i] ^ b[i];
    }
    res
}

impl SecretShare {
    pub fn encrypt(&self, index: u32, key: &PublicKey) -> EncryptedShare {
        let s = &self.0[index as usize];
        EncryptedShare(xor32(hash!(s * &key.1), s.pack()))
    }
}

impl ValidatedPublicShare {
    fn get_element(&self, index: usize) -> Point {
        if index < self.0.len() {
            self.0[index as usize]
        } else {
            expand(self.0.iter()).nth(index - self.0.len()).unwrap()
        }
    }

    pub fn try_decrypt(
        &self,
        index: usize,
        share: &EncryptedShare,
        key: &SecretKey,
    ) -> Result<DecryptedShare, DecryptionFailureProof> {
        let p = self.get_element(index);
        let ss = (&key.0 * &p).pack();
        if let Some(s) = Scalar::unpack(&xor32(hash!(&ss), share.0)) {
            if &s * &GT == p {
                return Ok(DecryptedShare(s));
            }
        }
        let kk = prs!(key.0, p);
        let c = hash_s!(&(key.1).0, p, &ss, &kk * &GT, &kk * &p);
        let r = kk - c * key.0;
        Err(DecryptionFailureProof((ss, r, c).pack()))
    }

    pub fn is_valid(
        &self,
        index: usize,
        share: &EncryptedShare,
        key: &PublicKey,
        proof: &DecryptionFailureProof,
    ) -> bool {
        let p = self.get_element(index);
        if let Some(s) = Scalar::unpack(&xor32(hash!(&proof.0[..32]), share.0)) {
            if &s * &GT == p {
                return false;
            }
        }
        let (ss, r, c) = try_unpack!(&proof.0);
        if hash_s!(&key.0, p, ss, vmul2(r, &G, c, &key.1), vmul2(r, &p, c, &ss)) != c {
            return false;
        }
        true
    }
}

#[derive(Clone)]
pub struct RandomEpoch(Box<[Point]>);
#[derive(Copy, Clone)]
pub struct RandomEpochSecret(Scalar);

impl RandomEpoch {
    pub fn from_shares(
        n: u32,
        k: u32,
        mut shares: impl Iterator<Item = ValidatedPublicShare>,
    ) -> Self {
        assert!(n >= k);
        let mut res = Vec::with_capacity(n as usize);
        match shares.next() {
            None => {
                res.resize_with(n as usize, Point::identity);
            }
            Some(s) => {
                assert!(s.0.len() == k as usize);
                res.extend_from_slice(s.0.deref());
                for s in shares {
                    assert!(s.0.len() == k as usize);
                    for i in 0..k as usize {
                        res[i] += s.0[i];
                    }
                }
                res.extend(expand::<Point, _>(res.iter()).take((n - k) as usize));
            }
        }
        RandomEpoch(res.into_boxed_slice())
    }

    pub fn compute_share(
        &self,
        round: &RandomRound,
        index: usize,
        secret: &RandomEpochSecret,
    ) -> RandomShare {
        let ss = (&secret.0 * &round.1).pack();
        let k = prs!(secret.0, &round.0);
        let c = hash_s!(self.0[index], &ss, &k * &GT, &k * &round.1);
        RandomShare((ss, k - c * secret.0, c).pack())
    }

    pub fn validate_share(
        &self,
        round: &RandomRound,
        index: usize,
        share: &RandomShare,
    ) -> Option<ValidatedRandomShare> {
        let key = self.0[index];
        let (ss, r, c) = try_unpack!(&share.0);
        let uss = try_unpack!(&ss);
        if hash_s!(key, &ss, vmul2(r, &G, c, &key), vmul2(r, &round.1, c, &uss)) != c {
            return None;
        }
        Some(ValidatedRandomShare(uss))
    }

    pub fn finalize(products: &[(u32, ValidatedRandomShare)]) -> [u8; 32] {
        let n = products.len();
        let mut coeff = Vec::with_capacity(n);
        for (i, (xi, _)) in products.iter().enumerate() {
            let mut v = if i & 1 != 0 { -Scalar::one() } else { Scalar::one() };
            for (xj, _) in &products[..i] {
                v *= Scalar::from(xi - xj);
            }
            for (xj, _) in &products[i + 1..] {
                v *= Scalar::from(xj - xi);
            }
            coeff.push(v);
        }
        Scalar::batch_invert(coeff.deref_mut());
        for (i, v) in coeff.iter_mut().enumerate() {
            for (x, _) in products[..i].iter().chain(&products[i + 1..]) {
                *v *= Scalar::from(x + 1);
            }
        }
        Point::vartime_multiscalar_mul(coeff, products.iter().map(|p| (p.1).0)).pack()
    }
}

impl RandomEpochSecret {
    pub fn from_shares(mut shares: impl Iterator<Item = DecryptedShare>) -> Self {
        RandomEpochSecret(match shares.next() {
            None => Scalar::zero(),
            Some(DecryptedShare(mut s)) => {
                for DecryptedShare(s2) in shares {
                    s += s2;
                }
                s
            }
        })
    }
}

#[derive(Copy, Clone)]
pub struct RandomRound([u8; 32], Point);
value_type!(pub, RandomShare, 96, "random share");
#[derive(Copy, Clone)]
pub struct ValidatedRandomShare(Point);
value_type!(pub, RandomValue, 32, "random value");

impl RandomRound {
    pub fn new(epoch_id: &[u8; 32], index: u32) -> Self {
        // We don't really need to compute Elligator twice, but curve25519-dalek doesn't provide a function which does it only once.
        let p = Point::from_hash(hasher!(Hash512, epoch_id, &index.to_le_bytes()));
        RandomRound(p.pack(), p)
    }
}
