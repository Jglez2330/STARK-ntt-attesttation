from attestation import Attestation
from algebra import *
from fast_stark import FastStark
from ip import ProofStream

if __name__ == '__main__':
    cfg = {1: [2,3],
           2: [5, 6],
           3: [4],
           4 : [8],
           5 : [7],
           6: [7],
           7:[9],
           8:[9]}
    a = Attestation(cfg)
    nine = FieldElement(9, Field.main())
    one_h = FieldElement(100, Field.main())
    trace = [FieldElement(i, Field.main()) for i in [100, 1, 2, 6, 7, 9] ]
    state = a.prove(Field.main().one(), nine, one_h, None, trace)
    air  = a.transition_constraints()
    boundary = a.boundary_constrains(one_h,Field.main().one(),nine)

    stark = FastStark(Field.main(), 8, 2, 2, 8, a.cycle_num)
    transition_zerofier, transition_zerofier_codeword, transition_zerofier_root = stark.preprocess()

    proof = stark.prove(state, air, boundary, transition_zerofier, transition_zerofier_codeword)
    verdict = stark.verify(proof, air, boundary, transition_zerofier_root)
    print(verdict)
