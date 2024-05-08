use std::time::Instant;

use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    for n in [10, 100, 1000, 10_000, 100_000] {
        let mut stdin = SP1Stdin::new();
        stdin.write(&n);

        // Generate the proof for the given program and input.
        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);
        let mut proof = client.prove(&pk, stdin).unwrap();

        println!("generated proof");

        // Read and verify the output.
        let _ = proof.public_values.read::<u32>();
        let a = proof.public_values.read::<u32>();
        let b = proof.public_values.read::<u32>();

        println!("a: {}", a);
        println!("b: {}", b);

        // Verify proof and public values
        client.verify(&proof, &vk).expect("verification failed");

        // Save the proof.
        proof
            .save("proof-with-pis.json")
            .expect("saving proof failed");

        println!("successfully generated and verified proof for the program!");

        //benchmark running
        let mut stdin = SP1Stdin::new();
        stdin.write(&n);
        let t = Instant::now();
        let proof = client.prove(&pk, stdin).unwrap();
        println!("=== Fibo({}) Proving time: {:?}", n, t.elapsed());
        let t = Instant::now();
        client.verify(&proof, &vk).expect("verification failed");
        println!("=== Fibo({}) Verifying time: {:?}", n, t.elapsed());
    }
}
