use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::pasta::{pallas, EqAffine};
use rand::{rngs::OsRng, Rng};

use std::time::Instant;

use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};

use halo2_proofs::{
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

#[derive(Clone)]
struct MyCircuit {
    input: Vec<u8>,
}

impl Circuit<pallas::Base> for MyCircuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { input: vec![] }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        Table16Chip::load(config.clone(), &mut layouter)?;
        let table16_chip = Table16Chip::construct(config);

        // Convert input bytes to BlockWords
        let mut input_blocks = Vec::new();
        for chunk in self.input.chunks(4) {
            let mut block = [0u8; 4];
            for (i, &byte) in chunk.iter().enumerate() {
                block[i] = byte;
            }
            input_blocks.push(BlockWord(Value::known(u32::from_be_bytes(block))));
        }

        // Pad the input to a multiple of BLOCK_SIZE
        let padded_len = ((self.input.len() + 8) / BLOCK_SIZE + 1) * BLOCK_SIZE;
        while input_blocks.len() < padded_len / 4 {
            input_blocks.push(BlockWord(Value::known(0)));
        }

        // Append the length of the message as a 64-bit big-endian integer
        let bit_len = (self.input.len() * 8) as u64;
        let len_bytes = bit_len.to_be_bytes();
        for &byte in &len_bytes {
            input_blocks.push(BlockWord(Value::known(byte as u32)));
        }

        Sha256::digest(table16_chip, layouter.namespace(|| "sha256"), &input_blocks)?;

        Ok(())
    }
}

fn main() {
    let mut rng = rand::thread_rng();
    for (k, n) in [(17, 10), (17, 100), (17, 1000), (19, 10_000), (22, 100_000)] {
        let input_data: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        // Initialize the polynomial commitment parameters
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(k); //ParamsIPA::new is TERRIBLE!

        let circuit = MyCircuit {
            input: input_data.clone(),
        };
        // Initialize the proving key
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");

        // Create a proof
        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit.clone()],
            &[],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        println!("=== sha2({}) Proving time: {:?}", n, t.elapsed());

        // Verify the proof
        let t = Instant::now();
        use halo2_proofs::poly::VerificationStrategy;
        let strategy = AccumulatorStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = verify_proof::<IPACommitmentScheme<_>, VerifierIPA<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[],
            &mut transcript,
        )
        .unwrap();
        assert!(strategy.finalize());
        println!("=== sha2({}) Verifying time: {:?}", n, t.elapsed());
    }
}
