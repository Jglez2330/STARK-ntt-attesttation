import time

from attestation import Attestation, load_cfg
from algebra import *
from fast_stark import FastStark
from ip import ProofStream

if __name__ == '__main__':

    cfg = load_cfg("/Users/jglez2330/Library/Mobile Documents/com~apple~CloudDocs/personal/STARK-ntt-attesttation/ZEKRA-STARK/embench-iot-applications/aha-mont64/numified_adjlist")
    path = "/Users/jglez2330/Library/Mobile Documents/com~apple~CloudDocs/personal/STARK-ntt-attesttation/ZEKRA-STARK/embench-iot-applications/aha-mont64/numified_path"
    #Time the execution

    a = Attestation(cfg)
    one_h = FieldElement(100, Field.main())
    state = a.prove( one_h,False, None, path,)
    boundary = a.boundary_constrains(one_h,a.start,a.end)

    stark = FastStark(Field.main(), 16, 8, 8, a.registers, a.cycle_num)
    air  = a.transition_constraints(stark.omicron)
    transition_zerofier, transition_zerofier_codeword, transition_zerofier_root = stark.preprocess()
    start = time.time()
    proof = stark.prove(state, air, boundary, transition_zerofier, transition_zerofier_codeword)
    end = time.time()
    verdict = stark.verify(proof, air, boundary, transition_zerofier_root)
    print(verdict)
    # print("Execution time: ", end - start)
    print("Execution time: ", end - start)
    #Size of the proof
    print("Size of the proof: ", len(proof))
