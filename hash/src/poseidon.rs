use crate::constants;
use ark_bn254::Fr;
use ark_ff::fields::Field;
use ark_ff::Zero;
use std::str::FromStr;

pub trait Sponge {
    fn absorb();
    fn squeeze();
    fn hash();
}

#[derive(PartialEq)]
pub enum PoseidonHashType {
    MerkleTree,
    ConstInputLen,
}

pub struct PoseidonParams {
    t: usize,
    alpha: usize,
    num_f: usize,
    num_p: usize,
    pub mds_matrix: Vec<Vec<Fr>>,
    pub round_constants: Vec<Fr>,
}

pub struct Poseidon {
    state: Vec<Fr>,
    params: PoseidonParams,
}

fn load_constants(t: usize, num_f: usize, num_p: usize) -> (Vec<Vec<Fr>>, Vec<Fr>) {
    let (c_strij, m_strij) = constants::constants();

    let c_str = &c_strij[t];
    let m_str = &m_strij[t];

    let mut round_constants: Vec<Fr> = Vec::with_capacity(t * (num_f + num_p));
    for c_str_i in c_str.iter().take(t * (num_f + num_p)) {
        let a: Fr = Fr::from_str(c_str_i).expect("a");
        round_constants.push(a);
    }

    let mut mds: Vec<Vec<Fr>> = Vec::new();
    for i in 0..t {
        let mut mds_i: Vec<Fr> = Vec::with_capacity(t);
        for j in 0..t {
            mds_i.push(Fr::from_str(m_str[i][j]).expect("s"));
        }
        mds.push(mds_i);
    }

    (mds, round_constants)
}

impl PoseidonParams {
    fn new(t: usize) -> Self {
        let mut params = PoseidonParams {
            t,
            alpha: 5,
            num_f: 57,
            num_p: 8,
            mds_matrix: Vec::new(),
            round_constants: Vec::new(),
        };
        (params.mds_matrix, params.round_constants) =
            load_constants(params.t, params.num_f, params.num_p);
        params
    }

    fn alpha(&self) -> usize {
        self.alpha
    }

    fn width(&self) -> usize {
        self.t
    }

    fn num_f(&self) -> usize {
        self.num_f
    }

    fn num_p(&self) -> usize {
        self.num_p
    }
}

impl Poseidon {
    pub fn new(mut state: Vec<Fr>, hash_type: PoseidonHashType) -> Self {
        let t = state.len() + 1;

        let domain_tag = if hash_type == PoseidonHashType::MerkleTree {
            ((2 ^ state.len()) + 1) as u128
        } else {
            (2 ^ 64) * state.len() as u128
        };

        // let domain_tag_fr = BigInt::from(domain_tag);
        let mut new_state: Vec<Fr> = vec![Fr::zero()];
        new_state.append(&mut state);
        Poseidon {
            state: new_state,
            params: PoseidonParams::new(t),
        }
    }

    fn sbox_full(&mut self) {
        for i in 0..self.params.width() {
            let temp = self.state[0];
            self.state[i] = self.state[0].square();
            self.state[i] = self.state[0].square();
            self.state[i] *= temp;
        }
    }
    fn sbox_partial(&mut self) {
        let temp = self.state[0];
        self.state[0] = self.state[0].square();
        self.state[0] = self.state[0].square();
        self.state[0] *= temp;
    }

    fn sbox(&mut self, round_i: usize) {
        if round_i < self.params.num_p / 2 || round_i > self.params.num_p / 2 + self.params.num_f {
            self.sbox_full()
        } else {
            self.sbox_partial()
        }
    }

    fn product_mds(&mut self, round_i: usize) {
        let mut new_state: Vec<Fr> = Vec::with_capacity(self.params.width() + 1);
        for i in 0..self.params.width() {
            let mut new_state_i = Fr::zero();
            for j in 0..self.params.width() {
                new_state_i += self.state[j] * self.params.mds_matrix[i][j];
            }
            new_state.push(new_state_i);
        }
        self.state = new_state
    }

    fn add_round_constants(&mut self, ith: usize) {
        for i in 0..self.params.width() {
            // println!(
            //     "ark: {:?}, state: {:?}",
            //     self.params.round_constants.len(),
            //     self.state.len()
            // );
            self.state[i] += &self.params.round_constants[ith * self.params.width() + i];
        }
    }

    pub fn hash(&mut self) -> Result<Fr, String> {
        let num_rounds = self.params.num_f + self.params.num_p;
        for i in 0..num_rounds {
            // println!("start round_i: {}, state: {:?}", i, self.state.len());
            self.add_round_constants(i);
            // println!("ark round_i: {}, state: {:?}", i, self.state.len());
            self.sbox(i);
            // println!("sbox round_i: {}, state: {:?}", i, self.state.len());
            self.product_mds(i);
            // println!("end round_i: {}, state: {:?}", i, self.state.len());
        }

        Ok(self.state[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_works() {
        let state: Vec<Fr> = vec![Fr::from(1), Fr::from(2)];
        let mut pos = Poseidon::new(state, PoseidonHashType::ConstInputLen);

        println!("state: {:?}", pos.state);
        println!("round_constants: {:?}", pos.params.round_constants.len());
        let out = pos.hash().unwrap_or(Fr::zero());
        assert_eq!(
            out.to_string(),
            "702818956448241653665554182341769666231371233761698089559867315561525558590"
        )
    }
}
