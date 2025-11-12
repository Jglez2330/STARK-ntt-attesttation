mod cfg;
use std::env::{self, args};
use std::fmt::Debug;
use cfg::{Cfg};
mod air;
use air::*;
use winterfell::{AcceptableOptions, Air, DefaultConstraintCommitment, FieldExtension, ProofOptions, Prover, Trace, TraceTable, crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256}, math::{FieldElement, fields::f64::BaseElement}, verify, VerifierError};
use log::trace;
use crate::{exe_path::{JmpType, parse_execution_path_file}, prover::StarkraProver};
mod prover;
// --- Demo ---
// To run: `rustc cfg.rs && ./cfg`
// fn main() {
//     // String example
//     let adj_str = vec![
//         ("A", vec!["B", "C"]),
//         ("B", vec!["D"]),
//         ("C", vec!["D"]),
//         ("D", vec![]),
//     ];
//     let cfg_s = Cfg::from_adjacency(adj_str);
//     println!("[String] Nodes: {:?}", cfg_s.nodes().collect::<Vec<_>>());
//     println!("[String] Edges: {:?}", cfg_s.edges().collect::<Vec<_>>());
//     println!(
//         "[String] Pred(D): {:?}",
//         cfg_s.predecessors(&Node::from("D"))
//     );
//
//     // Integer example
//     let adj_int = vec![
//         (10i32, vec![11, 12]),
//         (11i32, vec![13]),
//         (12i32, vec![13]),
//         (13i32, vec![]),
//     ];
//     let cfg_i = Cfg::from_adjacency(adj_int);
//     println!("[Int] Nodes: {:?}", cfg_i.nodes().collect::<Vec<_>>());
//     println!("[Int] Succ(11): {:?}", cfg_i.successors(&Node::from(11)));
// }
//

pub fn build_trace(start: BaseElement, steps: usize) -> TraceTable<BaseElement> {
    // One column, `steps` rows
    let mut trace = TraceTable::new(1, steps);

    // Fill the column with the recurrence: x_{i+1} = x_i^3 + 42
    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
        },
    );

    trace
}
// fn main() {
//     // 1) choose params
//     let start = BaseElement::new(3);
//     let steps = 1024usize;
//
//     // 2) build trace
//     let trace = build_trace(start, steps);
//     let end = trace.get(0, steps - 1);
//     let nonce = trace.get(0, steps - 1);
//
//     // ✅ Print the result
//     println!("Trace start value:  {}", start);
//     println!("Trace final value:  {}", end);
//     println!("Nonce (same as end): {}", nonce);
//     println!();
//
//     // 3) pick proof options (security vs speed)
//     let pub_inputs = PublicInputs { start, end, nonce };
//     let options = ProofOptions::new(
//         32,
//         8,
//         0,
//         FieldExtension::Quadratic,
//         4,
//         255,
//         winterfell::BatchingMethod::Linear,
//         winterfell::BatchingMethod::Linear,
//     );
//     let prover = StarkraProver::new(options);
//
//     // 4) generate proof
//     let proof = Prover::prove(&prover, trace).expect("prove");
//
//         // Print proof size
//     let proof_bytes = proof.to_bytes();
//     let proof_len = proof_bytes.len();
//     println!("--- Proof Info ---");
//     println!("Proof size: {} bytes ({:.2} KB)", proof_len, proof_len as f64 / 1024.0);
//     println!();
//
//     // 5) verify
//     let pub_inputs = PublicInputs { start, end, nonce };
//     let min_security = AcceptableOptions::MinConjecturedSecurity(95);
//     verify::<
//         StarkraAir,
//         Blake3_256<BaseElement>,
//         DefaultRandomCoin<Blake3_256<BaseElement>>,
//         MerkleTree<Blake3_256<BaseElement>>,
//     >(proof, pub_inputs, &min_security)
//     .expect("verify");
//
//     println!("✅ Proof generated and successfully verified!");
// }
//

mod exe_path;
// fn main() {
//     let args: Vec<String> = env::args().collect();
//     if args.len() != 2 {
//         eprintln!("Usage: {} <path_to_trace_file>", args[0]);
//         std::process::exit(1);
//     }
//
//     match parse_execution_path_file(&args[1]) {
//         Ok((list, initial, final_node)) => {
//             println!("list:");
//             for step in &list {
//                 let kind = match step.jmp_type {
//                     JmpType::Call => "call",
//                     JmpType::Jump => "jump",
//                     JmpType::Ret  => "ret",
//                 };
//
//                 match step.addrs.as_slice() {
//                     [a, b] => println!("  ({}, [{}, {}])", kind, a, b),
//                     [a]    => println!("  ({}, [{}])",     kind, a),
//                     other  => println!("  ({}, {:?})", kind, other),
//                 }
//             }
//             println!("initial: {:?}", initial);
//             println!("final:   {:?}", final_node);
//         }
//         Err(e) => {
//             eprintln!("Error: {e}");
//             std::process::exit(1);
//         }
//     }
// }
use std::time::Instant;

// Optional: tweak this if you want a hard warning threshold for proof size.
const PROOF_WARN_BYTES: usize = 25 * 1024 * 1024; // 25 MiB

fn fmt_bytes(n: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let n_f = n as f64;
    if n_f >= GB {
        format!("{:.2} GiB ({} bytes)", n_f / GB, n)
    } else if n_f >= MB {
        format!("{:.2} MiB ({} bytes)", n_f / MB, n)
    } else if n_f >= KB {
        format!("{:.2} KiB ({} bytes)", n_f / KB, n)
    } else {
        format!("{} bytes", n)
    }
}


pub fn print_trace_table_with_headers(trace: &TraceTable<BaseElement>, max_succ: usize) {
    let width = trace.width();
    let length = trace.length();

    // ---- build header names ----
    let mut headers = Vec::new();
    headers.push("nonce".to_string());
    headers.push("current".to_string());
    headers.push("stack".to_string());

    for i in 0..max_succ {
        headers.push(format!("nei{}", i));
    }

    headers.push("valid".to_string());
    headers.push("ret".to_string());
    headers.push("call".to_string());

    assert_eq!(headers.len(), width, "header/width mismatch");

    // ---- print headers ----
    print!("row |");
    for h in &headers {
        print!(" {:>7} |", h);
    }
    println!();

    // ---- separator ----
    print!("----+");
    for _ in &headers {
        print!("---------+");
    }
    println!();

    // ---- print rows ----
    for r in 0..length {
        print!("{:>3} |", r);
        for c in 0..width {
            let v = trace.get(c, r).as_int();
            print!(" {:>7} |", v);
        }
        println!();
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let cfg = Cfg::from_file(args[1].as_str()).expect("error cfg");
    let (path, a, b) = parse_execution_path_file(args[2].as_str()).expect("error");

    // 1) build trace (timed)
    let t_build_start = Instant::now();
    let trace = StarkraAir::build_trace(path, cfg.clone(), 123);
    let build_dur = t_build_start.elapsed();
    println!("Trace built in {:.3?}", build_dur);

    print_trace_table_with_headers(&trace, cfg.max_successors());
    // 2) public inputs
    let public_inputs = PublicInputs{
        start: BaseElement::from(a.expect("Error Start")),
        end:   BaseElement::from(b.expect("Error End")),
        nonce: BaseElement::new(123),
    };

    // 3) prover/options
    let options = ProofOptions::new(
        20,
        64,
        0,
        FieldExtension::Quadratic,
        4,
        255,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    );
    let prover = StarkraProver::new(options);

    // 4) generate proof (timed)
    let t_prove_start = Instant::now();
    let proof = Prover::prove(&prover, trace).expect("prove");
    let prove_dur = t_prove_start.elapsed();
    println!("Proving time: {:.3?}", prove_dur);

    // 4.1) proof size (and basic check)
    let proof_bytes = proof.to_bytes();
    let proof_len = proof_bytes.len();
    println!("Proof size: {}", fmt_bytes(proof_len));


    // 5) verify (timed)
    let min_security = AcceptableOptions::MinConjecturedSecurity(100);
    let t_verify_start = Instant::now();
    match verify::<
        StarkraAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, public_inputs, &min_security) {
        Ok(_) => {println!("Valid Proof")}
        Err(_) => {println!("Failed to verify proof")}
    }
    let verify_dur = t_verify_start.elapsed();
    println!(" Verification succeeded in {:.3?}", verify_dur);

    // 6) summary line
    println!(
        "Done. Trace build: {:.3?} | Prove: {:.3?} | Verify: {:.3?} | Proof: {}",
        build_dur, prove_dur, verify_dur, fmt_bytes(proof_len)
    );
}

