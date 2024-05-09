use std::time::Instant;

use rand::Rng;
use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    let mut rng = rand::thread_rng();
    for n in [10, 100, 1000, 10_000, 100_000] {
        let mut stdin = SP1Stdin::new();
        // let input = vec![123u8; n]; //FIXME from rand str
        let input: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        stdin.write(&input);

        // Generate the proof for the given program and input.
        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);
        let mut proof = client.prove(&pk, stdin).unwrap();

        println!("generated proof");

        // Read and verify the output.
        let _h = proof.public_values.read::<[u8; 32]>();
        println!("h: {:?}", _h);

        // Verify proof and public values
        client.verify(&proof, &vk).expect("verification failed");

        // Save the proof.
        proof
            .save("proof-with-pis.json")
            .expect("saving proof failed");

        println!("successfully generated and verified proof for the program!");

        //benchmark running
        let mut stdin = SP1Stdin::new();
        let input = vec![123u8; n]; //FIXME from rand str
        stdin.write(&input);
        let t = Instant::now();
        let proof = client.prove(&pk, stdin).unwrap();
        println!("=== sha2({}) Proving time: {:?}", n, t.elapsed());
        let t = Instant::now();
        client.verify(&proof, &vk).expect("verification failed");
        println!("=== sha2({}) Verifying time: {:?}", n, t.elapsed());
    }
}
