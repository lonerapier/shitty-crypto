pub fn add(left: usize, right: usize) -> usize {
    left + right
}

use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{
        short_weierstrass::{
            curves::bls12_381::curve::BLS12381Curve, point::ShortWeierstrassProjectivePoint,
        },
        traits::IsEllipticCurve,
    },
    unsigned_integer::element::UnsignedInteger,
};
pub fn public_key<const N: usize>(
    private_key: UnsignedInteger<N>,
) -> ShortWeierstrassProjectivePoint<BLS12381Curve> {
    BLS12381Curve::generator().operate_with_self(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn test_public_key() {
        let private_key: UnsignedInteger<1> = UnsignedInteger::from_u64(0x6C616D6264617370);
        let public_key = public_key(private_key);
        println!("public_key: {:?}", public_key.x().to_hex());
    }
}
