/* This crate is accompanying the Noir library at : https://github.com/jat9292/noir-elgamal/. 
do_compute_dlog is supposed to be called as a last step during decryption, taking as input the value returned by the exp_elgamal_decrypt Noir function.
This code is heavily inspired by zkay, see : https://github.com/eth-sri/zkay/blob/master/babygiant-lib/src/lib.rs
Two main differences with respect to zkay : 
1/ we replaced scalar multiplication inside the baby steps loop by point addition, this lead to a 7x speedup on average, as well as multithreading for another 2.5x improvement
allowing to decrypt  u40 instead of just u32 in less than 6.5 seconds (on a Mac M1 chip), this is why we replaced the max_bitwidth argument from 32 to 40 in the baby_giant call.
Even in the browser this should be practical for uint40 in less than 9s in the worst case (WASM overhead) when using num_threads=8.
2/ 2/ Another big difference is that the imported arkworks library uses the Edwards form instead of the Twisted Edwards form which is used in Noir for the baby Jubjub curve, 
so we did a coordinate transform to encode points in the Twisted Edwards form instead of the Edwards form, for using the same format as the Noir implementation. 
*/

use ark_ed_on_bn254::{EdwardsAffine as BabyJubJub, Fr, Fq, EdwardsParameters};
use ark_ff::{BigInteger256, field_new, PrimeField, BigInteger, SquareRootField};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ec::twisted_edwards_extended::{GroupProjective, GroupAffine};
use hex;
use std::collections::HashMap;
use std::sync::mpsc;
use std::{thread, process};
use regex::Regex;

fn baby_giant(max_bitwidth: u64, a: &GroupAffine<EdwardsParameters>, b: &GroupProjective<EdwardsParameters>, num_threads: u64) -> Option<u64> {
    let m = 1u64 << (max_bitwidth / 2);
    let chunk_size = m / num_threads;
    let (tx, rx) = mpsc::channel();

    for idx in 0..num_threads {
        let a = a.clone();
        let b = b.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            let start = idx * chunk_size;
            let end = if idx == num_threads - 1 { m } else { start + chunk_size };
            let mut table = HashMap::new();

            // NOTE: equality and hashing (used for HashMap) does not perform as expected
            // for projective representation (because coordinates are ambiguous), so switching
            // to affine coordinates here
            let mut v =  a.mul(Fr::new(BigInteger256::from(start))).into_affine();
            let a1 = a.mul(Fr::new(BigInteger256::from(1))).into_affine();

            for j in start..end { // baby_steps
                table.insert(v, j);
                v =  v + a1; // original zkay version was doing scalar multiplication inside the loop, we replaced it by constant increment, because addition is faster than scalar multiplication on the elliptic curve
            }
            let am = a.mul(Fr::new(BigInteger256::from(m)));
            let mut gamma = b.clone();

            for i in 0..m { // giant_steps
                if let Some(j) = table.get(&gamma.into_affine()) {
                    tx.send(Some(i * m + j)).unwrap();
                    return;
                }
                gamma = gamma - &am;
                
            }
            let _ = tx.send(None);
            
        });
    }

    let mut result = None;
    for _ in 0..num_threads {
        if let Some(res) = rx.recv().unwrap() {
            result = Some(res);
            break;
        }
    }
    result
}

fn parse_be_bytes_str(s: &str) -> BigInteger256 {
    let s = s.trim_start_matches("0x");
    let le_str = reverse_byte_order(s);
    parse_le_bytes_str(&le_str)
}

fn reverse_byte_order(s: &str) -> String {
    s.as_bytes()
        .chunks_exact(2)
        .rev()
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect()
}

fn parse_le_bytes_str(s: &str) -> BigInteger256 {
    let mut buffer = [0u8; 32];     // 32 bytes for 256 bits

    let v = hex::decode(s).unwrap();
    assert_eq!(v.len(), 32);
    let v = v.as_slice();
    for i in 0..32 {
        buffer[i] = v[i];
    }

    let mut bi = BigInteger256::new([0; 4]);
    bi.read_le(&mut buffer.as_ref()).unwrap();
    return bi;
}

fn pad_with_zeros(input: &str) -> String {
    if input.len() < 66 && input.starts_with("0x") {
        let padding_needed = 66 - input.len();
        format!("0x{}{}", "0".repeat(padding_needed), &input[2..])
    } else {
        input.to_string()
    }
}

fn is_valid_format(input: &str) -> bool {
    let re = Regex::new(r"^0x[a-fA-F0-9]{64}$").unwrap();
    re.is_match(input)
}

// This function will compute the Discrete Logarithm of a point on the Baby Jubjub curve, in Twisted Edwards form.
// The embedded plaintext should be a u40 (unsigned integer smaller than 1099511627775) or else the program will not find a valid discrete logarithm and panic.
// x and y are strings representing coordinates of the embedded plaintext and should have the same format as the values returned by the exp_elgamal_decrypt in the noir-elgamal package.
// i.e  x and y should be hexadecimal strings representing two bytes of size 32 at most. 
// Eg of valid inputs: x="0xbb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051" and y="0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b".
// num_thread is the number of threads used for parallelizing the baby-step giant-step algorithm.
pub fn do_compute_dlog(x: &str, y: &str, num_threads: u64) -> u64 {
    let padded_x = pad_with_zeros(&x);
    let padded_y = pad_with_zeros(&y);
    
    if !is_valid_format(&padded_x) || !is_valid_format(&padded_y)  {
        eprintln!(r#"Invalid input format : x and y should be hexadecimal strings representing two bytes of size 32 at most. 
Also make sure the coordinates x and y are points on the Baby Jubjub curve (Twisted Edwards form) and follow the same format as returned by the exp_elgamal_decrypt function in the noir-elgamal package).
Eg of valid inputs: x="0xbb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051" and y="0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b".
Also please keep in mind that the embedded plaintext corresponding to the (x,y) point should not exceed type(uint40).max, i.e 1099511627775 or else the program will not find a valid discrete logarithm and panic."#);
        process::exit(1);
    }

    let coeff_twisted = field_new!(Fq,"168700").sqrt().unwrap(); // this coeff_twisted was introduced to transform the coordinates of baby Jubjub points from the Twisted Edwards form coming from Noir, to the Edwards form compatible with arkworks
    let gx = field_new!(Fq, "5299619240641551281634865583518297030282874472190772894086521144482721001553")*coeff_twisted;
    let gy = field_new!(Fq, "16950150798460657717958625567821834550301663161624707787222815936182638968203");
    let a = BabyJubJub::new(gx, gy); // the base point of the twisted Edwards form of Baby Jubjub : https://eips.ethereum.org/EIPS/eip-2494#forms-of-the-curve
    assert!(BabyJubJub::is_on_curve(&a), "(x,y) is not a valid point on Baby Jubjub curve in Twisted Edwards form");
    assert!(BabyJubJub::is_in_correct_subgroup_assuming_on_curve(&a), "(x,y) is not a valid point in the prime subgroup of Baby Jubjub curve in Twisted Edwards form");
    let bx = Fq::from_repr(parse_be_bytes_str(&padded_x)).unwrap()*coeff_twisted;
    let by = Fq::from_repr(parse_be_bytes_str(&padded_y)).unwrap();
    let b = BabyJubJub::new(bx, by);
    assert!(BabyJubJub::is_on_curve(&b), "(x,y) is not a valid point on Baby Jubjub curve in Twisted Edwards form");
    assert!(BabyJubJub::is_in_correct_subgroup_assuming_on_curve(&b), "(x,y) is not a valid point in the prime subgroup of Baby Jubjub curve in Twisted Edwards form");
    let b = b.mul(Fr::new(BigInteger256::from(1)));

    baby_giant(40, &a, &b, num_threads).expect("The Baby-step Giant-step algorithm was unable to solve the Discrete Logarithm. Make sure that the embedded plaintext is an unsigned integer between 0 and 1099511627775.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_dlog1() {
        let dlog = do_compute_dlog("0x05e712cbd0bee349ab612d42b81672d48546ab29a90798ad2b88f64585f0c805",
                                   "0xbdb2d53146a7d643d6c6870319fe563a253f78c18a48e3fa45b6d7d9d3c310",2);
        assert_eq!(65545, dlog);
    }

    
    #[test]
    fn test_compute_dlog2() {
        let dlog = do_compute_dlog("0xf57b238724df2c542888b0df066af2e47f5a3b54efd22e0eeb63e830cdd3ca",
                                   "0x0a7a0495c2be1431a515c4eb5480cec8328028598cbf23a60c8ad08363983b12",2);
        assert_eq!(4294967295, dlog);
    }

    #[test]
    fn test_compute_dlog3() {
        let dlog = do_compute_dlog("0x2f38eeff5a5e7c9cb7f297bebd43d488354a35867b67e4147620893c025985f7",
                                   "0x011f455e2ad1c9ff8086a6f00fa560afc82f9b4dfb93db0c124edde66730dbda",3);
        assert_eq!(943594123598, dlog);
    }

    #[test]
    fn test_compute_dlog4() {
        let dlog = do_compute_dlog("0x084957e99aabdff4f3d79b0da6601dadbdbcaa864a97b50bf7230673262ed002",
                                   "0x06b45565a8859505a8971e35d409d1fb33381589ac2fa4d7e59ce7c7d6619784",3);
        assert_eq!(1099511627775, dlog); // max value authorized (type(uint40).max)
    }
}