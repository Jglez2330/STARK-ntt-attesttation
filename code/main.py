
import time
import sys
from Attestation import Attestation
from algebra import *
from fast_stark import FastStark
from ip import ProofStream
def load_trace_from_file(path):
    execution_path = {}
    with open(path, 'r') as file:
        lines = file.readlines()
        # Create a list to store the content
        # Iterate through each line
        start = True
        for line in lines:
            # Remove the newline character and split by comma
            parts = line.strip().split(' ')
            if start:
                start = False
                split_list= parts[0].strip().split('=')
                execution_path["start"] = FieldElement(int(split_list[1]), Field.main())
                split_list= parts[1].strip().split('=')
                execution_path["end"] = FieldElement(int(split_list[1]), Field.main())
                start_node = {}
                start_node["type"] = "start"
                start_node["dest"] = execution_path["start"]
                start_node["return"] = execution_path["start"]
                execution_path["path"] = [start_node]
                continue
            # select the second element
            if "call" in parts:
                jmp = {}
                jmp["type"] = "call"
                jmp["dest"] = FieldElement(int(parts[1]), Field.main())
                jmp["return"] = FieldElement(int(parts[2]), Field.main())
                execution_path["path"].append(jmp)
            elif "ret" in parts:
                jmp = {}
                jmp["type"] = "ret"
                jmp["dest"] = FieldElement(int(parts[1]), Field.main())
                jmp["return"] = FieldElement(int(parts[1]), Field.main())
                execution_path["path"].append(jmp)

            else:
                jmp = {}
                jmp["type"] = "jmp"
                jmp["dest"] = FieldElement(int(parts[1]), Field.main())
                jmp["return"] = FieldElement(int(parts[1]), Field.main())
                execution_path["path"].append(jmp)
            # Append the second element to the content list
    return execution_path
def load_cfg(path):
    cfg = {}
    with open(path, 'r') as file:
        lines = file.readlines()
        # Create a list to store the content
        # Iterate through each line
        for line in lines:
            # Remove the newline character and split by comma
            parts = line.strip().split(' ')
            # select the first element
            src = int(parts[0])
            dests = [int(dest) for dest in parts[1:]]
            cfg[src] = dests
        return cfg
if __name__ == '__main__':
    cfg_path = sys.argv[1]
    path = sys.argv[2]

    cfg = load_cfg(cfg_path);
    #Time the execution
    time_pre = time.time()

    a = Attestation(cfg)
    one_h = FieldElement(1254, Field.main())
    execution = load_trace_from_file(path)
    state = a.trace(one_h, execution["start"], execution["end"], execution["path"])
    boundary = a.boundary_constraints(one_h,a.start,a.end)
    stark = FastStark(Field.main(), 16, 32, 128, a.num_registers, a.num_cycles, transition_constraints_degree=a.max_adjacency+1)
    air  = a.transition_constraints(stark.omicron)
    transition_zerofier, transition_zerofier_codeword, transition_zerofier_root = stark.preprocess()
    end_pre = time.time()
    start = time.time()
    proof = stark.prove(state, air, boundary, transition_zerofier, transition_zerofier_codeword)
    end = time.time()
    start_veriftime = time.time()
    verdict = stark.verify(proof, air, boundary, transition_zerofier_root)
    end_veriftime = time.time()
    print(verdict)
    # print("Execution time: ", end - start)
    print("Execution time: ", end - start)
    print("Execution time verif: ", end_veriftime - start_veriftime)
    print("Execution time pre: ", end_pre - time_pre)
    #Size of the proof
    print("Size of the proof: ", len(proof))
