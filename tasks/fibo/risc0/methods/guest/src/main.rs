#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

// use core::hint::black_box;

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let n: u32 = env::read();
    let answer = fibonacci(n);
    env::commit(&answer);
}

fn fibonacci(n: u32) -> u32 {
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let temp = b;
        b = a + b;
        a = temp;
    }
    a
}
