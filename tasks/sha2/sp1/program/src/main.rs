//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let result = gen_sha256_opt(input);
    sp1_zkvm::io::commit::<[u8; 32]>(&result.into());
}

#[allow(unused)]
#[inline(always)]
fn gen_sha256(input: Vec<u8>) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.into()
}

#[allow(unused)]
#[inline(always)]
fn gen_sha256_opt(input: Vec<u8>) -> [u8; 32] {
    use sha2_v0_10_8::Digest;
    let mut hasher = sha2_v0_10_8::Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.into()
}
