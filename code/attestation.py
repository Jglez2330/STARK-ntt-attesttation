import math
import random

from ip import *
from fri import *

from algebra import *
from univariate import *
from multivariate import *
from cfg import *
from hashlib import blake2b
from merkle import *
from poseidon import *
# This function generates/emulates executions for the CFG
def gen_exe_paths(cfg, start, end, path=None):
    if path is None:
        path = []
    path = path + [start]
    if start == end:
        return [path]

    if start not in cfg:
        return []

    paths = []
    for node in cfg[start]:
        if node not in path:  # to avoid cycles
            newpaths = gen_exe_paths(cfg, node, end, path)
            for newpath in newpaths:
                paths.append(newpath)
    return paths
def hash_leaves(leaves):
    leaves_hashes = []
    for leaf in leaves:
        leaves_hashes.append(blake2b(leaf).digest())
    return leaves_hashes
def next_power_of_2(n):
    if n < 1:
        return 1
    return 2 ** math.ceil(math.log2(n))
def blockify(lst, block_size, padding_value=None):
    if block_size <= 0:
        raise ValueError("Block size must be a positive integer.")

    blocks = [lst[i:i + block_size] for i in range(0, len(lst), block_size)]

    # Pad the last block if it's smaller than block_size
    if blocks and len(blocks[-1]) < block_size:
        blocks[-1].extend([padding_value] * (block_size - len(blocks[-1])))

    return blocks


def is_transition_valid(cfg:dict, src, dst):
    result = 0
    lst_dest:list = cfg[src.value]
    if dst.value in lst_dest:
        result = 1
    return result




class Attestation:
    def __init__(self, cfg):
        self.cfg = cfg
        self.leaves_transitions = get_list_hash_transitions(self.cfg)
        #self.hash_leaves = hash_leaves(self.leaves_transitions)
        self.root_transitions = Merkle.commit(self.leaves_transitions)
        self.adjlist_hashes = get_adjlist_hash(self.cfg)

    def create_trace(self, path, nonce = 0, padding_value = 0, falsify_path_list=[]):
        trace = [FieldElement(nonce, Field.main())] + [FieldElement(node, Field.main()) for node in path]
        bytes_hashes = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in trace]
        random_index_to_append_falsify = random.randint(0, len(bytes_hashes)-1)
        hash_false_path = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in falsify_path_list]
        bytes_hashes = bytes_hashes[:random_index_to_append_falsify] + hash_false_path + bytes_hashes[random_index_to_append_falsify:]
        hash_trace = [FieldElement(int.from_bytes(bytes(bytes_hash, "UTF-8")), Field.main()) for bytes_hash in bytes_hashes]

        return hash_trace

    def prove(self, start_node, end_node, nonce, proof:ProofStream, path=None, exp_factor = 1024):
        # Generate the proof
        # proof = ProofStream()
        # proof.write(start_node)
        # proof.write(end_node)
        # proof.write(nonce)
        # return proof
        #Start the prove by adding the nonce from the verifier to the trace
        if path is None: path = gen_exe_paths(self.cfg, start_node, end_node) if path == []:
                return None
            path = path[0]

        trace = self.create_trace(path, nonce)
        root_pow1 = next_power_of_2(len(trace))
        field = Field.main()

        g = field.generator()
        h = field.primitive_nth_root(root_pow1*exp_factor)

        G = [g^i for i in range(len(trace))]
        H = [h^i for i in range(root_pow1*exp_factor)]

        fx = Polynomial.interpolate_domain(G, trace)

        #Push start, end and nonce
        proof.push(FieldElement(nonce, field))
        proof.push(FieldElement(start_node, field))
        proof.push(FieldElement(end_node, field))

        # Get random obfuscation w
        w = field.sample(proof.serialize())
        H_w = [h*w for h in H]
        fx_exp_eval = fx.evaluate_domain(H_w)
        fx_root =  Merkle.commit(fx_exp_eval)

        proof.push(fx_exp_eval);
        proof.push(fx_root);

        transitions = []
        trace_transitions = trace[1:]
        for i in range(len(trace_transitions)-1):
            src = trace_transitions[i]
            dst = trace_transitions[i+1]
            transition_str = str((src, dst))
            hash = blake2b(bytes(transition_str, encoding="UTF-8")).hexdigest()
            transitions.append(FieldElement(int.from_bytes(bytes(hash, "UTF-8")), field))
        root_pow = next_power_of_2(len(transitions))

        h2 = field.primitive_nth_root(root_pow*exp_factor)

        H2 = [h2^i for i in range(root_pow*exp_factor)]
        G2 = [g^i for i in range(len(transitions))]

        gx = Polynomial.interpolate_domain(G2, transitions)

        w2 = field.sample(proof.serialize())
        H2_w = [h*w2 for h in H2]

        gx_exp_eval = gx.evaluate_domain(H2_w)
        gx_root = Merkle.commit(gx_exp_eval)

        proof.push(gx_root)
        proof.push(gx_exp_eval)

        proof.push(trace)

        #Generate the computational polynomial that will restrain the trace to the expected behaviour
        #Boundary contrains first
        #nonce
        hash_nonce_bytes = blake2b(bytes(str(nonce).encode("UTF-8"))).hexdigest()
        hash_nonce = FieldElement(int.from_bytes(bytes(hash_nonce_bytes, "UTF-8")), Field.main())
        X = Polynomial([field.zero(), field.one()])
        p0_num = fx - Polynomial([hash_nonce])
        p0_dem = X - Polynomial([G[0]])

        alpha0 = field.sample(proof.serialize())
        p0:Polynomial = p0_num/p0_dem * Polynomial([alpha0])
        p0_eval = p0.evaluate_domain(H2_w)
        proof.push(p0_eval);

        #start node
        hash_start_bytes = blake2b(bytes(str(start_node).encode("UTF-8"))).hexdigest()
        hash_start = FieldElement(int.from_bytes(bytes(hash_start_bytes, "UTF-8")), Field.main())
        p1_num = fx - Polynomial([hash_start])
        p1_dem = X - Polynomial([G[1]])
        alpha1 = field.sample(proof.serialize())
        p1 = p1_num/p1_dem * Polynomial([alpha1])
        #p1_eval = p1.evaluate_domain(H2_w)
        #proof.push(p1_eval);

        #end node
        hash_end_bytes = blake2b(bytes(str(end_node).encode("UTF-8"))).hexdigest()
        hash_end = FieldElement(int.from_bytes(bytes(hash_end_bytes, "UTF-8")), Field.main())
        p2_num = fx - Polynomial([hash_end])
        p2_dem = X - Polynomial([G[len(trace)-1]])
        alpha2 = field.sample(proof.serialize())
        p2 = p2_num/p2_dem * Polynomial([alpha2])
        #p2_eval = p2.evaluate_domain(H2_w)
        #proof.push(p2_eval);

        #transitions
        pn_num:list[Polynomial] = []
        pn_dem:list[Polynomial] = []
        for i in range(len(transitions)):
            is_valid = FieldElement(is_transition_valid(self.adjlist_hashes, trace[i+1], trace[i+2]), Field.main());
            transition_num = gx - Polynomial([transitions[i]*is_valid])
            pn_num.append(transition_num)
            pn_dem.append(X - Polynomial([G[i]]))

        pn = []
        pn_eval = []
        for i in range(len(pn_num)):
            alpha_n = field.sample(proof.serialize())
            pn.append(pn_num[i]/pn_dem[i]*Polynomial([alpha_n]))
            #pn_eval.append(pn[-1].evaluate_domain(H2_w))
            #proof.push(pn_eval[-1])

        cp = p0 + p1 + p2
        cp_eval = cp.evaluate_domain(H_w)
        mk_cp_root = Merkle.commit(cp_eval)


        fri = Fri(w, h, root_pow1, exp_factor, 4)
        fri_proof = ProofStream()
        a = fri.prove(cp_eval, fri_proof)
        b = fri.verify(fri_proof, a)

        return trace, proof