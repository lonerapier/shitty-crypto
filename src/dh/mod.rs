//! Contains implementation of Diffie-Hellman Key Exchange protocol

use rand::{thread_rng, Rng};

use crate::{
  curve::{pairing::Pairing, AffinePoint, EllipticCurve},
  field::FiniteField,
};

/// Trait to define Diffie-Hellman key exchange
pub trait DH<F: FiniteField> {
  /// generate a shared key between two parties
  fn generate_shared_key(&mut self, another_pub_key: F);
}

/// Diffie-Hellman struct based on a finite field
#[derive(Debug, Default)]
pub struct FFDH<F: FiniteField> {
  private_key:    u32,
  /// public key for communication rounds
  pub public_key: F,
  shared_key:     F,
}

impl<F: FiniteField> FFDH<F> {
  /// generate new FFDH struct
  pub fn new() -> Self {
    let mut rng = thread_rng();
    let priv_key: u32 = rng.gen();
    let pub_key = F::PRIMITIVE_ELEMENT * F::from(priv_key);
    FFDH { private_key: priv_key, public_key: pub_key, shared_key: F::ZERO }
  }

  /// create a shared key between two parties
  pub fn generate_shared_key(&mut self, another_pub_key: F) {
    assert!(another_pub_key != self.public_key);

    self.shared_key = another_pub_key * F::from(self.private_key);
  }

  /// shared key getter
  pub fn shared_key(&self) -> F { self.shared_key }
}

/// Diffie-Hellman struct based on Elliptic curve
#[derive(Debug)]
pub struct ECDH<C: EllipticCurve> {
  private_key:    u32,
  /// public key of a participant
  pub public_key: AffinePoint<C>,
  shared_key:     AffinePoint<C>,
}

impl<C: EllipticCurve + std::cmp::PartialEq> ECDH<C> {
  /// creates a new private public key pair for an ECDH participant
  pub fn new() -> Self {
    let mut rng = thread_rng();
    let priv_key: u32 = rng.gen::<u32>() % C::ScalarField::ORDER as u32;
    let pub_key = C::GENERATOR * priv_key;
    Self { private_key: priv_key, public_key: pub_key, shared_key: AffinePoint::Infinity }
  }

  /// generate shared key between two participants and assign shared key to a participant
  pub fn generate_shared_key(&mut self, another_pub_key: AffinePoint<C>) {
    assert!(another_pub_key != self.public_key);

    self.shared_key = another_pub_key * self.private_key;
  }

  /// shared key getter
  pub fn shared_key(&self) -> AffinePoint<C> { self.shared_key }
}

impl<C: EllipticCurve> Default for ECDH<C> {
  fn default() -> Self {
    Self { private_key: 0, public_key: AffinePoint::Infinity, shared_key: AffinePoint::Infinity }
  }
}

/// Tripartite ECDH based on tate pairing
pub struct TripartiteECDH<C: Pairing> {
  private_key:    u32,
  /// public key of each participant
  pub public_key: AffinePoint<C>,
  shared_key:     C::BaseField,
}

impl<C: Pairing> TripartiteECDH<C> {
  /// creates a new default element of tripartite ECDH
  pub fn new() -> Self {
    let mut rng = thread_rng();
    let priv_key: u32 = rng.gen::<u32>() % C::ScalarField::ORDER as u32;
    let pub_key = C::GENERATOR * priv_key;
    Self { private_key: priv_key, public_key: pub_key, shared_key: C::BaseField::default() }
  }

  /// generate a shared key between three participants using tate pairing.
  pub fn generate_shared_key(&mut self, a: AffinePoint<C>, b: AffinePoint<C>)
  where [(); C::R_TORSION_SIZE]: {
    assert!(self.public_key != a);
    assert!(self.public_key != b);

    let cube_root_of_unity = C::BaseField::primitive_root_of_unity(3);
    let b_map = if let AffinePoint::<C>::Point(x, y) = b {
      AffinePoint::<C>::new(x * cube_root_of_unity, y)
    } else {
      panic!("a's public key not a point");
    };

    self.shared_key = C::pairing(a, b_map).pow(self.private_key as usize);
  }
}

impl<C: Pairing> Default for TripartiteECDH<C> {
  fn default() -> Self {
    Self {
      private_key: 0,
      public_key:  AffinePoint::Infinity,
      shared_key:  C::BaseField::default(),
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::{
    curve::pluto_curve::{PlutoBaseCurve, PlutoExtendedCurve},
    field::prime::PlutoBaseField,
  };

  #[test]
  fn dh() {
    let mut alice = FFDH::<PlutoBaseField>::new();
    let mut bob = FFDH::<PlutoBaseField>::new();

    alice.generate_shared_key(bob.public_key);
    bob.generate_shared_key(alice.public_key);

    assert_eq!(alice.shared_key(), bob.shared_key());
  }

  #[test]
  fn ecdh() {
    let mut alice = ECDH::<PlutoBaseCurve>::new();
    let mut bob = ECDH::<PlutoBaseCurve>::new();
    while bob.public_key == alice.public_key {
      bob = ECDH::<PlutoBaseCurve>::new();
    }

    alice.generate_shared_key(bob.public_key);
    bob.generate_shared_key(alice.public_key);

    assert_eq!(alice.shared_key(), bob.shared_key());
  }

  #[test]
  fn tdh() {
    let mut alice = TripartiteECDH::<PlutoExtendedCurve>::new();
    let mut bob = TripartiteECDH::new();
    let mut carol = TripartiteECDH::new();

    alice.generate_shared_key(bob.public_key, carol.public_key);
    bob.generate_shared_key(alice.public_key, carol.public_key);
    carol.generate_shared_key(bob.public_key, alice.public_key);

    assert_eq!(alice.shared_key, bob.shared_key);
    assert_eq!(bob.shared_key, carol.shared_key);
  }
}
