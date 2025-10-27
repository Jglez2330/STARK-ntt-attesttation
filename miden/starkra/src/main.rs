use miden_core::AdviceMap;
use miden_processor::ExecutionOptions;
use miden_processor::Felt;
use miden_vm::{
    AdviceInputs, AdviceProvider, Assembler, DefaultHost, Program, ProgramInfo, ProvingOptions,
    StackInputs, Word, assembly::DefaultSourceManager, execute, execute_iter, prove, verify,
};
use std::fs;
use std::sync::Arc;

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
    // let  _ = fs::read_to_string(path).expect("Failed to read execution trace file");
    let jmp = Felt::new(0);
    let call = Felt::new(1);
    let ret = Felt::new(2);
    let start = Felt::new(0);
    let end = Felt::new(10);

    let mut advice_map = Vec::new();

    advice_map.push((
        Word::new([Felt::new(256), Felt::new(0), Felt::new(0), Felt::new(0)]),
        vec![Felt::new(0x0)],
    ));
    advice_map.push((
        Word::new([Felt::new(256), Felt::new(0), Felt::new(0), Felt::new(1)]),
        vec![Felt::new(0x1), Felt::new(0x10)],
    ));
    advice_map.push((
        Word::new([Felt::new(256), Felt::new(0), Felt::new(0), Felt::new(2)]),
        vec![Felt::new(0x10)],
    ));
    //
    advice_map.push((
        Word::new([Felt::new(256), Felt::new(256), Felt::new(0), Felt::new(0)]),
        vec![jmp],
    ));
    advice_map.push((
        Word::new([Felt::new(256), Felt::new(256), Felt::new(0), Felt::new(1)]),
        vec![call],
    ));
    advice_map.push((
        Word::new([Felt::new(256), Felt::new(256), Felt::new(0), Felt::new(2)]),
        vec![ret],
    ));

    (advice_map, start, end)
}

fn load_cfg(path: &str) -> Vec<(Word, Vec<Felt>)>{

    let cfg = Vec::new();

    cfg.push((
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
        vec![Felt::new(0x0), Felt::new(0x1)],
    ));


    cfg
}

fn main() {
    // instantiate the assembler
    let mut assembler = Assembler::default().with_debug_mode(true);

    // load an execution trace from a file
    // the trace contains the sequence of jumps, calls and returns
    // As well as the start and end addresses
    let (trace, start, end) = load_execution_trace("execution_trace.txt");

    let mut advice_inputs = AdviceInputs::default().with_map(trace.clone());
    let mut stack_values = StackInputs::try_from_ints(vec![start.as_int(), end.as_int()]).unwrap();

    // this is our program, we compile it from assembly code
    let program = assembler
        .assemble_program(fs::read_to_string("./src/starkra.masm").unwrap())
        .unwrap();
    // instantiate default execution options
    let exec_options = ExecutionOptions::default();
    // instantiate a default host (with no advice inputs)
    let mut host = DefaultHost::default();

    // let's execute it and generate a STARK proof
    let (outputs, proof) = prove(
        &program,
        stack_values.clone(),
        advice_inputs.clone(),
        &mut DefaultHost::default(), // we'll be using a default host
        ProvingOptions::default(),   // we'll be using default options
    )
    .unwrap();

    // the output should be 8
    assert_eq!(8, outputs.first().unwrap().as_int());

    // let's verify program execution
    match verify(
        ProgramInfo::from(program.clone()),
        StackInputs::try_from_ints(vec![start.as_int(), end.as_int()]).unwrap(),
        outputs,
        proof,
    ) {
        Ok(_) => println!("Execution verified!"),
        Err(msg) => println!("Something went terribly wrong: {}", msg),
    }
    // now, execute the same program in debug mode and iterate over VM states
    // now, execute the same program in debug mode and iterate over VM states
    for vm_state in execute_iter(&program, stack_values, advice_inputs, &mut host) {
        match vm_state {
            Ok(vm_state) => println!("{:?}\n", vm_state),
            Err(_) => println!("something went terribly wrong!"),
        }
    }
}
