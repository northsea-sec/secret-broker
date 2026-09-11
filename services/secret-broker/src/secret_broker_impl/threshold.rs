//! Feldman-style verifiable secret sharing over the P-256 scalar field.
//!
//! The redeem secret is reduced into a canonical P-256 scalar and shared as the
//! constant term of a degree-(k-1) polynomial. Public commitments to the
//! coefficients are stored alongside the sealed broker record so that each
//! supplied share can be verified before reconstruction.

use p256::{
    elliptic_curve::{
        group::{
            ff::{Field, PrimeField},
            GroupEncoding,
        },
        ops::Reduce,
    },
    AffinePoint, CompressedPoint, FieldBytes, ProjectivePoint, Scalar, U256,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const SHARE_LENGTH: usize = 32;
pub const COMMITMENT_LENGTH: usize = 33;

#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("threshold must be >= 1 and <= num_shares")]
    InvalidParams,
    #[error("insufficient shares: need {threshold}, got {got}")]
    InsufficientShares { threshold: u8, got: usize },
    #[error("duplicate share x-coordinate")]
    DuplicateShares,
    #[error("invalid share length")]
    InvalidShareLength,
    #[error("share is not a canonical P-256 scalar")]
    InvalidShareScalar,
    #[error("missing threshold commitments")]
    MissingCommitments,
    #[error("invalid commitment count: expected {expected}, got {got}")]
    InvalidCommitmentCount { expected: usize, got: usize },
    #[error("invalid commitment length")]
    InvalidCommitmentLength,
    #[error("invalid commitment encoding")]
    InvalidCommitmentEncoding,
    #[error("share does not match commitments")]
    CommitmentMismatch,
}

/// A single share: evaluation point x (1..=255) and 32-byte scalar share value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub x: u8,
    pub y: Vec<u8>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct SplitResult {
    pub shares: Vec<Share>,
    pub commitments: Vec<Vec<u8>>,
}

/// Reduce arbitrary 32-byte material into the canonical P-256 scalar encoding
/// used on the verifiable threshold path.
pub fn canonical_secret_bytes(secret: &[u8; 32]) -> [u8; SHARE_LENGTH] {
    scalar_to_array(secret_scalar_from_bytes(secret))
}

/// Split a 32-byte secret into n verifiable shares with threshold k.
pub fn split(
    secret: &[u8; 32],
    threshold: u8,
    num_shares: u8,
) -> Result<SplitResult, ThresholdError> {
    if threshold < 1 || threshold > num_shares {
        return Err(ThresholdError::InvalidParams);
    }
    if num_shares == 0 {
        return Err(ThresholdError::InvalidParams);
    }

    let mut coeffs = Vec::with_capacity(threshold as usize);
    coeffs.push(secret_scalar_from_bytes(secret));
    for _ in 1..threshold {
        coeffs.push(Scalar::random(&mut OsRng));
    }

    let commitments = coeffs
        .iter()
        .map(|coeff| commitment_for_scalar(*coeff))
        .collect::<Vec<_>>();

    let shares = (1..=num_shares)
        .map(|x| {
            let y = eval_poly(&coeffs, scalar_from_x(x));
            Share {
                x,
                y: scalar_to_array(y).to_vec(),
            }
        })
        .collect::<Vec<_>>();

    coeffs.fill(Scalar::ZERO);

    Ok(SplitResult {
        shares,
        commitments,
    })
}

/// Verify and reconstruct a canonical 32-byte secret from k or more shares.
pub fn reconstruct(
    shares: &[Share],
    threshold: u8,
    commitments: &[Vec<u8>],
) -> Result<[u8; SHARE_LENGTH], ThresholdError> {
    if shares.len() < threshold as usize {
        return Err(ThresholdError::InsufficientShares {
            threshold,
            got: shares.len(),
        });
    }
    validate_commitments(commitments, threshold)?;

    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return Err(ThresholdError::DuplicateShares);
            }
        }
    }

    let decoded_commitments = commitments
        .iter()
        .map(|commitment| decode_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;

    let share_scalars = shares
        .iter()
        .map(|share| {
            verify_share_with_commitments(share, &decoded_commitments)?;
            share_scalar(share)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut secret = Scalar::ZERO;

    for (i, share) in shares.iter().enumerate() {
        let xi = scalar_from_x(share.x);
        let yi = share_scalars[i];
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;

        for (j, other) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = scalar_from_x(other.x);
            numerator *= xj;
            denominator *= xj - xi;
        }

        let denominator_inv =
            Option::<Scalar>::from(denominator.invert()).ok_or(ThresholdError::DuplicateShares)?;
        secret += yi * numerator * denominator_inv;
    }

    Ok(scalar_to_array(secret))
}

fn validate_commitments(commitments: &[Vec<u8>], threshold: u8) -> Result<(), ThresholdError> {
    if commitments.is_empty() {
        return Err(ThresholdError::MissingCommitments);
    }
    if commitments.len() != threshold as usize {
        return Err(ThresholdError::InvalidCommitmentCount {
            expected: threshold as usize,
            got: commitments.len(),
        });
    }
    Ok(())
}

fn scalar_from_x(x: u8) -> Scalar {
    Scalar::from(x as u64)
}

fn secret_scalar_from_bytes(secret: &[u8; SHARE_LENGTH]) -> Scalar {
    let field_bytes: FieldBytes = (*secret).into();
    <Scalar as Reduce<U256>>::reduce_bytes(&field_bytes)
}

fn scalar_to_array(value: Scalar) -> [u8; SHARE_LENGTH] {
    let bytes = value.to_bytes();
    let mut out = [0u8; SHARE_LENGTH];
    out.copy_from_slice(bytes.as_slice());
    out
}

fn commitment_for_scalar(coeff: Scalar) -> Vec<u8> {
    (ProjectivePoint::GENERATOR * coeff)
        .to_bytes()
        .as_slice()
        .to_vec()
}

fn decode_commitment(bytes: &[u8]) -> Result<ProjectivePoint, ThresholdError> {
    if bytes.len() != COMMITMENT_LENGTH {
        return Err(ThresholdError::InvalidCommitmentLength);
    }
    let encoded = CompressedPoint::clone_from_slice(bytes);
    let affine = Option::<AffinePoint>::from(AffinePoint::from_bytes(&encoded))
        .ok_or(ThresholdError::InvalidCommitmentEncoding)?;
    Ok(ProjectivePoint::from(affine))
}

fn share_scalar(share: &Share) -> Result<Scalar, ThresholdError> {
    if share.y.len() != SHARE_LENGTH {
        return Err(ThresholdError::InvalidShareLength);
    }
    let mut encoded = FieldBytes::default();
    encoded.copy_from_slice(&share.y);
    Option::<Scalar>::from(Scalar::from_repr(encoded)).ok_or(ThresholdError::InvalidShareScalar)
}

fn verify_share_with_commitments(
    share: &Share,
    commitments: &[ProjectivePoint],
) -> Result<(), ThresholdError> {
    let y = share_scalar(share)?;
    let x = scalar_from_x(share.x);
    let mut rhs = ProjectivePoint::IDENTITY;
    let mut x_power = Scalar::ONE;

    for commitment in commitments {
        rhs += *commitment * x_power;
        x_power *= x;
    }

    let lhs = ProjectivePoint::GENERATOR * y;
    if lhs == rhs {
        Ok(())
    } else {
        Err(ThresholdError::CommitmentMismatch)
    }
}

fn eval_poly(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        result *= x;
        result += coeff;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn split_reconstruct_1_of_1() {
        let secret = scalar_to_array(Scalar::random(&mut OsRng));
        let split = split(&secret, 1, 1).unwrap();
        assert_eq!(split.shares.len(), 1);
        let recovered = reconstruct(&split.shares, 1, &split.commitments).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_reconstruct_2_of_3() {
        let secret = scalar_to_array(Scalar::random(&mut OsRng));
        let split = split(&secret, 2, 3).unwrap();
        assert_eq!(split.shares.len(), 3);
        let r1 = reconstruct(&split.shares[0..2], 2, &split.commitments).unwrap();
        assert_eq!(r1, secret);
        let r2 = reconstruct(&split.shares[1..3], 2, &split.commitments).unwrap();
        assert_eq!(r2, secret);
        let combo = vec![split.shares[0].clone(), split.shares[2].clone()];
        let r3 = reconstruct(&combo, 2, &split.commitments).unwrap();
        assert_eq!(r3, secret);
    }

    #[test]
    fn split_reconstruct_3_of_5() {
        let secret = scalar_to_array(Scalar::random(&mut OsRng));
        let split = split(&secret, 3, 5).unwrap();
        assert_eq!(split.shares.len(), 5);
        let r = reconstruct(&split.shares[0..3], 3, &split.commitments).unwrap();
        assert_eq!(r, secret);
        let r2 = reconstruct(&split.shares[2..5], 3, &split.commitments).unwrap();
        assert_eq!(r2, secret);
    }

    #[test]
    fn insufficient_shares_fails() {
        let secret = [0xAA; 32];
        let split = split(&secret, 3, 5).unwrap();
        let result = reconstruct(&split.shares[0..2], 3, &split.commitments);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_params() {
        let secret = [0; 32];
        assert!(split(&secret, 0, 5).is_err());
        assert!(split(&secret, 6, 5).is_err());
    }

    #[test]
    fn tampered_share_fails_commitment_check() {
        let secret = scalar_to_array(Scalar::random(&mut OsRng));
        let split = split(&secret, 2, 3).unwrap();
        let mut tampered = split.shares[0].clone();
        tampered.y[0] ^= 0x01;
        let err = reconstruct(&[tampered, split.shares[1].clone()], 2, &split.commitments)
            .expect_err("tampered share must fail");
        assert!(matches!(
            err,
            ThresholdError::CommitmentMismatch | ThresholdError::InvalidShareScalar
        ));
    }

    #[test]
    fn canonicalizes_non_scalar_secret_bytes() {
        let secret = [0xFF; 32];
        let split = split(&secret, 2, 3).unwrap();
        let recovered = reconstruct(&split.shares[0..2], 2, &split.commitments).unwrap();
        assert_eq!(recovered, canonical_secret_bytes(&secret));
        assert_ne!(recovered, secret);
    }

    #[test]
    fn commitments_are_compressed_points() {
        let secret = scalar_to_array(Scalar::random(&mut OsRng));
        let split = split(&secret, 3, 5).unwrap();
        assert_eq!(split.commitments.len(), 3);
        for commitment in split.commitments {
            assert_eq!(commitment.len(), COMMITMENT_LENGTH);
            assert!(STANDARD.encode(commitment).len() >= 44);
        }
    }
}
