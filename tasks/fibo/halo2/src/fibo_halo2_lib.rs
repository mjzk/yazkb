use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
        flex_gate::MultiPhaseThreadBreakPoints,
        GateChip, GateInstructions,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{verify_proof, Circuit, ProvingKey},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::VerifierSHPLONK,
                strategy::SingleStrategy,
            },
        },
    },
    utils::{fs::gen_srs, ScalarField},
    AssignedValue,
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark_shplonk, read_snark, PoseidonTranscript},
    NativeLoader,
};
use std::{env::var, fs, path::PathBuf, time::Instant};

#[allow(unused_imports)]
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
// use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct CircuitInput {
    pub x: usize, // field element
}

// this algorithm takes a public input x, computes x^2 + 72, and outputs the result as public output
fn bench_zk_circuit<F: ScalarField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let k = input.x;
    let ctx = builder.main(0);
    // first we load a number `x` into as system, as a "witness"
    // let x = ctx.load_witness(x);
    // by default, all numbers in the system are private
    // we can make it public like so:
    // make_public.push(x);
    let gate = GateChip::<F>::default();
    let mut a = ctx.load_witness(F::ZERO);
    let mut b = ctx.load_witness(F::ONE);
    let mut c = ctx.load_witness(F::ONE);
    for _r in 0..k - 1 {
        c = gate.add(ctx, Existing(a), Existing(b));
        a = b;
        b = c;
    }
    // println!("vc: {:?}", vc);
    make_public.push(c);
    // assert_eq!(*x.value() * x.value() + c, *out.value());
}

pub fn main() {
    for nth in [10, 100, 1000, 10_000, 100_000] {
        let k = next_bin_log(4 * nth);
        run_on_inputs(nth as _, k);
    }
}

fn next_bin_log(num: u64) -> u32 {
    (num as f64).log2().ceil() as u32
}

pub fn run_on_inputs(nth: usize, k: u32) {
    println!("\ninput nth: {}, k: {}", nth, k);
    let name = "fibo";

    let data_path = PathBuf::from("data");
    fs::create_dir_all(&data_path).unwrap();

    let params = gen_srs(k);
    println!("Universal trusted setup (unsafe!) available at: params/kzg_bn254_{k}.srs");

    // Keygen
    let circuit = create_circuit(CircuitBuilderStage::Keygen, None, &params, nth);
    let pk: ProvingKey<G1Affine> = gen_pk(&params, &circuit, None);
    let c_params = circuit.params();
    let break_points = circuit.break_points();

    // Prove
    //warmup
    let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
    if snark_path.exists() {
        fs::remove_file(&snark_path).unwrap();
    }
    let pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints) =
        (c_params.clone(), break_points.clone());
    prove(pinning, &params, nth, &pk, &snark_path);

    let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
    if snark_path.exists() {
        fs::remove_file(&snark_path).unwrap();
    }
    let start = Instant::now();
    let pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints) = (c_params, break_points);
    prove(pinning, &params, nth, &pk, &snark_path);
    let prover_time = start.elapsed();
    println!("=== Fibo({}) Proving time: {:?}", nth, prover_time);
    // println!("Snark written to: {snark_path:?}");

    // Verify
    let mut circuit = create_circuit(CircuitBuilderStage::Keygen, None, &params, nth);
    let vk = pk.get_vk();
    let snark_path = data_path.join(PathBuf::from(format!("{name}.snark")));
    let snark = read_snark(&snark_path)
        .unwrap_or_else(|e| panic!("Snark not found at {snark_path:?}. {e:?}"));

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(&snark.proof[..]);
    let instance = &snark.instances[0][..];
    //warmup
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        _,
        _,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        &vk,
        strategy.clone(),
        &[&[instance]],
        &mut transcript,
    )
    .unwrap();

    let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(&snark.proof[..]);
    let start = Instant::now();
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        _,
        _,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        &vk,
        strategy,
        &[&[instance]],
        &mut transcript,
    )
    .unwrap();
    let verification_time = start.elapsed();
    println!(
        "=== Fibo({}) Snark verified successfully in {:?}",
        nth, verification_time
    );
    circuit.clear();
}

fn prove(
    pinning: (BaseCircuitParams, Vec<Vec<usize>>),
    params: &ParamsKZG<Bn256>,
    private_inputs: usize,
    pk: &ProvingKey<G1Affine>,
    snark_path: &PathBuf,
) {
    let circuit = create_circuit(
        CircuitBuilderStage::Prover,
        Some(pinning),
        params,
        private_inputs,
    );
    gen_snark_shplonk(params, pk, circuit, Some(snark_path));
}

fn create_circuit(
    stage: CircuitBuilderStage,
    pinning: Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)>,
    params: &ParamsKZG<Bn256>,
    private_inputs: usize,
) -> BaseCircuitBuilder<Fr> {
    let mut builder = BaseCircuitBuilder::from_stage(stage);
    if let Some((params, break_points)) = pinning {
        builder.set_params(params);
        builder.set_break_points(break_points);
    } else {
        let k = params.k() as usize;
        // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
        let lookup_bits: Option<usize> = var("LOOKUP_BITS")
            .map(|str| {
                let lookup_bits = str.parse::<usize>().unwrap();
                // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
                assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
                lookup_bits
            })
            .ok();
        // we initiate a "thread builder". This is what keeps track of the execution trace of our program. If not in proving mode, it also keeps track of the ZK constraints.
        builder.set_k(k);
        if let Some(lookup_bits) = lookup_bits {
            builder.set_lookup_bits(lookup_bits);
        }
        builder.set_instance_columns(1);
    };

    // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
    // we need a 64-bit number as input in this case
    // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
    let mut assigned_instances = vec![];
    bench_zk_circuit(
        &mut builder,
        CircuitInput { x: private_inputs },
        &mut assigned_instances,
    );
    if !assigned_instances.is_empty() {
        assert_eq!(
            builder.assigned_instances.len(),
            1,
            "num_instance_columns != 1"
        );
        builder.assigned_instances[0] = assigned_instances;
    }

    if !stage.witness_gen_only() {
        // now `builder` contains the execution trace, and we are ready to actually create the circuit
        // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
        let minimum_rows = var("MINIMUM_ROWS")
            .unwrap_or_else(|_| "20".to_string())
            .parse()
            .unwrap();
        builder.calculate_params(Some(minimum_rows));
    }

    builder
}
