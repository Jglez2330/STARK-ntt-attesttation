from attestation import Attestation
from ip import ProofStream

if __name__ == '__main__':
    cfg = {1: [2,3],
           2: [4],
           3: [5]}
    a = Attestation(cfg)
    proof = ProofStream()
    a.prove(1, 5, 4, proof, None)