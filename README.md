# babygiant-alt-bn128
A Rust crate implementing a multi-threaded version of the baby-step giant-step algorithm on the Baby Jubjub curve (it is the curve whose base field is the scalar field of alt-bn-128 aka bn254) to decrypt u40 integers.
This is an accompanying crate for the Noir package [noir-elgamal](https://github.com/jat9292/noir-elgamal).

Please refer to the accompanying [npm package](https://github.com/jat9292/babyjubjub-utils) if you want to use a WASM version of this algorithm in a front-end.

⚠️ **Warning:** the current implementation is vulnerable to timing attacks, as the running time depends on the input. Please keep this in mind and exercise extra caution if you wish to use it in production.

## How to use
First, decrypt a point in embedded form using the `exp_elgamal_decrypt` function from [noir-elgamal](https://github.com/jat9292/noir-elgamal).

For example, this circuit should output the plaintext value `42` embedded as a point on the Baby Jubjub curve:
```rust
use dep::elgamal::{priv_to_pub_key,exp_elgamal_encrypt,exp_elgamal_decrypt};
use dep::std;

fn main(){
  let plaintext = 42;
  let private_key = 0x04d73359c9166e49aafaf9a4852eaa4dceb2c26878196b10e9048004ff5cc20c;
  let pub_key = priv_to_pub_key(private_key);
  let randomness = 0x03f90f366f9fd55bb1335eac3b11f2190f2ce9ff1769db241edaa7774136099b;
  let encrypted_point = exp_elgamal_encrypt(pub_key, plaintext, randomness);
  let decrypted_point = exp_elgamal_decrypt(private_key, encrypted_point);
  std::println(decrypted_point);
}
```

Indeed, running `nargo execute` should return the following point in a terminal: 
```
Point { x: 0x06184da392a17823e9c1d38cb50980b17150ffa411965b03f0b0200d9557daa9, y: 0x244a710118db92636e46e3f97bd80093ba7026ff97ca32d387145337e250549c }
```

For the last step of decryption, i.e to recover the original plaintext (as an unsigned integer of size 40 bits) from the previous embedded form, you can import this crate in a Rust project by adding the following dependency in `Cargo.toml` : 
```
[dependencies]
babygiant-alt-bn128 = "0.1.1"
```

And then use the following code in `src/main.rs`: 

```rust
use babygiant_alt_bn128::do_compute_dlog;

fn main() {
    let num_threads = 5;
    let dlog = do_compute_dlog("0x06184da392a17823e9c1d38cb50980b17150ffa411965b03f0b0200d9557daa9",
    "0x244a710118db92636e46e3f97bd80093ba7026ff97ca32d387145337e250549c",num_threads);
    assert!(42== dlog);
}
```

You can check that the baby-step giant-step algorithm is indeed able to recover the original plaintext value `42` by running : 
```
cargo run --release
```

The Rust program should run successfully in less than 2 seconds on a modern computer.

## Technical description
This crate is accompanying the Noir package at : https://github.com/jat9292/noir-elgamal/. 

`do_compute_dlog` is the main function in this crate, it is supposed to be called as a last step during decryption, taking as input the value returned by the [`exp_elgamal_decrypt`](https://github.com/jat9292/noir-elgamal/blob/v0.0.1/src/lib.nr#L50) Noir function.

This code is heavily inspired by [zkay](https://github.com/eth-sri/zkay/blob/master/babygiant-lib/src/lib.rs) and uses the [arkworks](https://github.com/arkworks-rs) crate as its main dependency.

Two main differences with respect to zkay : 

1/ We replaced scalar multiplication inside the baby steps loop by point addition, this lead to a 7x speedup on average, as well as multithreading for another 2.5x improvement
allowing to decrypt  `u40` instead of just `u32` in less than 6 seconds (on a Mac M1 chip), this is why we replaced the max_bitwidth argument from `32` to `40` in the `baby_giant` call.
Even in the browser (see the accompanying [npm package](https://github.com/jat9292/babyjubjub-utils)), it is now practical to decrypt a `u40` in less than 9s in the worst case (WASM overhead) when using a `num_threads` between `5` and `8`.

2/ Another big difference is that the imported arkworks library uses the Edwards form instead of the Twisted Edwards form which is used in Noir for the Baby Jubjub curve, so we did a coordinate transform to encode points in the Twisted Edwards form instead of the Edwards form, for using the same format as the Noir implementation. 

Here is the function signature :

```rust
pub fn do_compute_dlog(x: &str, y: &str, num_threads: u64) -> u64
```

This function will compute the Discrete Logarithm of a point on the Baby Jubjub curve, in Twisted Edwards form.
The embedded plaintext should be a `u40` (i.e an unsigned integer smaller than `1099511627775`) or else the program will not find a valid discrete logarithm and panic.

`x` and `y` are strings representing coordinates of the embedded plaintext and should have the same format as the values returned by the `exp_elgamal_decrypt` in the `noir-elgamal` package, i.e  `x` and `y` should be hexadecimal strings representing two bytes arrays of size `32` at most. 
Eg of valid inputs: `x="0xbb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051"` and `y="0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b"`.
Keep also in mind that if `(x,y)` is not a valid point on the Baby Jubjub curve in Twisted Edwards form, the program will panic.

`num_thread` is the number of threads used for parallelizing the baby-step giant-step algorithm.
