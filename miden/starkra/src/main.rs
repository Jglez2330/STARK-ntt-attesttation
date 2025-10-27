use miden_core::AdviceMap;
use miden_processor::ExecutionOptions;
use miden_processor::Felt;
use miden_vm::{
    AdviceInputs, AdviceProvider, Assembler, DefaultHost, Program, ProgramInfo, ProvingOptions,
    StackInputs, Word, assembly::DefaultSourceManager, execute, execute_iter, prove, verify,
};
use std::fs;
use std::fs::read_to_string;
use std::sync::Arc;
use std::time::Instant;
use std::str::FromStr;

fn load_execution_trace(path: &str) -> (Vec<(Word, Vec<Felt>)>, Felt, Felt) {
    // In a real scenario, you would load the execution trace from a file or other source.
    // Here, we just return a dummy trace for demonstration purposes.
    // Each line starts with the operation jmp, call or ret from the program
    // jmp 0x0
    // call 0x1
    // ret 0x2
    // ...
    //
    // JMP only has the address, CALL has address and return address, RET has only return address
    // Read the trace on the path and parse it into Felt values
    // Read whole file
    let content = fs::read_to_string(path)
        .expect("Failed to read execution trace file");

    // We'll store:
    //  - per-step operands
    //  - per-step opcode tags
    let mut operand_entries: Vec<(Word, Vec<Felt>)> = Vec::new();
    let mut opcode_entries: Vec<(Word, Vec<Felt>)> = Vec::new();

    // We'll also grab start/end from the header line
    let mut start_node: Option<Felt> = None;
    let mut end_node: Option<Felt> = None;

    // We'll enumerate the *instruction* lines starting at 0
    // i.e. first non-header line => idx 0, next => idx 1, ...
    let mut instr_idx: u32 = 0;

    for (line_no, raw_line) in content.lines().enumerate() {
        // Trim and skip empty
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if line_no == 0 {
            // expect: "initial_node=0 final_node=30"
            // we'll parse it loosely
            // split by whitespace => ["initial_node=0", "final_node=30"]
            let mut init_tmp: Option<u64> = None;
            let mut final_tmp: Option<u64> = None;

            for part in line.split_whitespace() {
                if let Some(rest) = part.strip_prefix("initial_node=") {
                    init_tmp = u64::from_str(rest).ok();
                } else if let Some(rest) = part.strip_prefix("final_node=") {
                    final_tmp = u64::from_str(rest).ok();
                }
            }

            let init_val = init_tmp.expect("missing initial_node in header");
            let final_val = final_tmp.expect("missing final_node in header");

            start_node = Some(Felt::new(init_val));
            end_node = Some(Felt::new(final_val));
            continue;
        }

        // past header: must be an instruction line
        // formats:
        //   "jump A"
        //   "call A R"
        //   "ret R"
        let mut parts = line.split_whitespace();

        let op_str = parts
            .next()
            .expect("malformed trace line: missing opcode");

        let (operands_felts, opcode_tag_felt) = match op_str {
            "jump" | "jmp" => {
                // 1 operand
                let addr_str = parts
                    .next()
                    .expect("jump requires 1 operand <addr>");
                // allow hex like 0x10 or decimal like 16
                let addr_val = parse_num(addr_str);

                (
                    vec![Felt::new(addr_val)],
                    Felt::new(0), // jump tag
                )
            }
            "call" => {
                // 2 operands
                let addr_str = parts
                    .next()
                    .expect("call requires 2 operands <addr> <retaddr>");
                let retaddr_str = parts
                    .next()
                    .expect("call requires 2 operands <addr> <retaddr>");

                let addr_val = parse_num(addr_str);
                let retaddr_val = parse_num(retaddr_str);

                (
                    vec![Felt::new(addr_val), Felt::new(retaddr_val)],
                    Felt::new(1), // call tag
                )
            }
            "ret" => {
                // 1 operand (return addr)
                let retaddr_str = parts
                    .next()
                    .expect("ret requires 1 operand <retaddr>");
                let retaddr_val = parse_num(retaddr_str);

                (
                    vec![Felt::new(retaddr_val)],
                    Felt::new(2), // ret tag
                )
            }
            other => {
                panic!("unknown opcode `{}` in trace", other);
            }
        };

        // Build the Words (keys):
        // operand map key: [256, 0,   0,   idx]
        // opcode  map key: [256, 256, 0,   idx]
        let idx_felt = Felt::new(instr_idx as u64);

        let operand_key = Word::new([
            Felt::new(256),
            Felt::new(0),
            Felt::new(0),
            idx_felt,
        ]);

        let opcode_key = Word::new([
            Felt::new(256),
            Felt::new(256),
            Felt::new(0),
            idx_felt,
        ]);

        operand_entries.push((operand_key, operands_felts));
        opcode_entries.push((opcode_key, vec![opcode_tag_felt]));

        instr_idx += 1;
    }

    // stitch the two maps together in one Vec<(Word, Vec<Felt>)>
    // order doesn't *have* to match your dummy, but we'll do operands first then opcodes,
    // like you did.
    let mut advice_map = Vec::new();
    advice_map.extend(operand_entries);
    advice_map.extend(opcode_entries);

    let start = start_node.expect("no initial_node parsed");
    let end = end_node.expect("no final_node parsed");

    (advice_map, start, end)
}

// helper: parse decimal like "30" or hex like "0x1f"
fn parse_num(txt: &str) -> u64 {
    if let Some(hex) = txt.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .expect("invalid hex number in trace")
    } else {
        u64::from_str(txt)
            .expect("invalid decimal number in trace")
    }
}

fn load_cfg(path: &str) -> Vec<(Word, Vec<Felt>)> {
    let mut cfg = Vec::new();

    //CFG is structured as where each line is the adjecency list for a given node
    //line 0: 0 1 2, node 0, edges to 1 and 2
    let mut result = Vec::new();

    for line in read_to_string(path).unwrap().lines() {
        result.push(line.to_string())
    }

    for (i, line) in result.iter().enumerate() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let node = parts[0].parse::<u64>().unwrap();
        let mut edges = Vec::new();
        for part in &parts[1..] {
            let edge = part.parse::<u64>().unwrap();
            edges.push(Felt::new(edge));
        }
        cfg.push((
            Word::new([
                Felt::new(0),
                Felt::new(0),
                Felt::new(0),
                Felt::new(node),
            ]),
            edges,
        ));
    }

    // cfg.push((
    //     Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
    //     vec![Felt::new(0x1)],
    // ));
    // cfg.push((
    //     Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]),
    //     vec![Felt::new(0x2)],
    // ));
    // cfg.push((
    //     Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
    //     vec![Felt::new(0x10), Felt::new(0x11)],
    // ));
    //
    //
    cfg
}

fn main() {
    // instantiate the assembler
    let mut assembler = Assembler::default().with_debug_mode(true);

    // load an execution trace from a file
    // the trace contains the sequence of jumps, calls and returns
    // As well as the start and end addresses
    let (trace, start, end) = load_execution_trace("./src/num_path");
    let cfg = load_cfg("./src/adj_list");

    let mut advice_inputs = AdviceInputs::default().with_map(trace.clone());
    let advice_inputs = advice_inputs.with_map(cfg.clone());
    let mut stack_values = StackInputs::try_from_ints(vec![start.as_int(), end.as_int()]).unwrap();

    // this is our program, we compile it from assembly code
    let program = assembler
        .assemble_program(fs::read_to_string("./src/starkra.masm").unwrap())
        .unwrap();
    // instantiate default execution options
    let exec_options = ExecutionOptions::default().with_debugging(true);
    // let exec_options = ExecutionOptions::default();
    // instantiate a default host (with no advice inputs)
    let mut host = DefaultHost::default();
    let trace = execute(
        &program,
        stack_values.clone(),
        advice_inputs.clone(),
        &mut host,
        exec_options,
    )
    .unwrap();

    // let's execute it and generate a STARK proof
    // time proof generation
    // #[cfg(feature = "std")]
    let now = Instant::now();
    let (outputs, proof) = prove(
        &program,
        stack_values.clone(),
        advice_inputs.clone(),
        &mut DefaultHost::default(), // we'll be using a default host
        ProvingOptions::default(),   // we'll be using default options
    )
    .unwrap();
    println!("Generated proof in {} ms", now.elapsed().as_millis());

    // let's verify program execution
    let ver_now = Instant::now();
    match verify(
        ProgramInfo::from(program.clone()),
        StackInputs::try_from_ints(vec![start.as_int(), end.as_int()]).unwrap(),
        outputs,
        proof,
    ) {
        Ok(_) => println!("Execution verified!"),
        Err(msg) => println!("Something went terribly wrong: {}", msg),
    }
    println!("Verified proof in {} ms", ver_now.elapsed().as_millis());
    // now, execute the same program in debug mode and iterate over VM states
    // now, execute the same program in debug mode and iterate over VM states
    // for vm_state in execute_iter(&program, stack_values, advice_inputs, &mut host) {
    //     match vm_state {
    //         Ok(vm_state) => println!("{:?}\n", vm_state),
    //         Err(_) => println!("something went terribly wrong!"),
    //     }
    // }
}
