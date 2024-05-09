// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Instant;

use rand::Rng;
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use sha_methods::{HASH_ELF, HASH_ID};

fn bench_hash(input: Vec<u8>, n: usize) {
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let elf = HASH_ELF;
    let id = HASH_ID;

    let prover = default_prover();
    let receipt = prover.prove(env, elf).unwrap();
    receipt.verify(id).expect("receipt verification failed");

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();
    let t = Instant::now();
    let prover = default_prover();
    let receipt = prover.prove(env, elf).unwrap();
    println!("=== sha2({}) Proving time: {:?}", n, t.elapsed());

    let _h: Digest = receipt.journal.decode().unwrap();
    println!("h: {:?}", _h);

    let t = Instant::now();
    receipt.verify(id).expect("receipt verification failed");
    println!("=== sha2({}) Proving time: {:?}", n, t.elapsed());
}

fn main() {
    let mut rng = rand::thread_rng();
    for n in [10, 100, 1000, 10_000, 100_000] {
        let input: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        bench_hash(input, n);
    }
}

#[cfg(test)]
mod tests {
    use sha_methods::{HASH_ID, HASH_RUST_CRYPTO_ID};

    #[test]
    fn hash_abc() {
        let (digest, receipt) = super::bench_hash("abc", false);
        receipt.verify(HASH_ID).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }

    #[test]
    fn hash_abc_rust_crypto() {
        let (digest, receipt) = super::bench_hash("abc", true);
        receipt.verify(HASH_RUST_CRYPTO_ID).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }
}
