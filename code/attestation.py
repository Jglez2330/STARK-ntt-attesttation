import math
import random

import poseidon

from ip import *
from fri import *

from algebra import *
from univariate import *
from multivariate import *
from cfg import *
from hashlib import blake2b
from merkle import *
from poseidon import *

poseidon_hash_f, t = poseidon.case_simple()

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

class Attestation:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cycle_num = 0
        self.registers = 0
        self.hash_transitions = self.get_list_hash_transitions()
        self.field = Field.main()
    #This function gets a cfg and get all the transition on a hash
    #i,e H(a,b) a->b
    def get_list_hash_transitions(self):
        transitions = set()
        for src in self.cfg:
            dests = self.cfg[src]
            for dest in dests:
                transitions.add((src, dest))
        hash_transitions = []
        for transition in transitions:
            src = FieldElement(transition[0], Field.main())
            dest = FieldElement(transition[1], Field.main())
            hash_transitions.append(self.hash_poseidon([src, dest]))
        return hash_transitions
    def create_trace(self, path, nonce = 0, padding_value = 0, falsify_path_list=[]):
        trace = [FieldElement(nonce, Field.main())] + [FieldElement(node, Field.main()) for node in path]
        bytes_hashes = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in trace]
        random_index_to_append_falsify = random.randint(0, len(bytes_hashes)-1)
        hash_false_path = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in falsify_path_list]
        bytes_hashes = bytes_hashes[:random_index_to_append_falsify] + hash_false_path + bytes_hashes[random_index_to_append_falsify:]
        hash_trace = [FieldElement(int.from_bytes(bytes(bytes_hash, "UTF-8")), Field.main()) for bytes_hash in bytes_hashes]

        return hash_trace
    def load_trace_from_file(self, path):
        call_stack = []
        return_stack = []
        with open(path, 'r') as file:
            lines = file.readlines()
            # Create a list to store the content
            content = []
            # Iterate through each line
            start = True
            for line in lines:
                # Remove the newline character and split by comma
                parts = line.strip().split(' ')
                if start:
                    start = False
                    content.append(line)
                    continue
                # select the second element
                if "call" in parts:
                    second_element = parts[1]
                    call_stack.append(parts[2])
                elif "ret" in parts:
                    second_element = parts[1]
                    return_stack.append(parts[1])
                else:
                    second_element = parts[1]
                # Append the second element to the content list
                content.append(second_element)
        return content, call_stack, return_stack

    def execute(self, nonce, start, end, trace=None, call_stack=None, return_stack=None):
        if trace is None:
            execution, call_stack, return_stack = self.load_trace_from_file("/Users/jglez2330/Library/Mobile Documents/com~apple~CloudDocs/personal/STARK-attesttation/ZEKRA-STARK/embench-iot-applications/aha-mont64/numified_path")
            trace = execution[1:]

        return nonce + trace
    def hash_poseidon(self, list:list[FieldElement]):
        vec = [elment.value for elment in list]


        result = poseidon_hash_f.run_hash(vec)

        return FieldElement(int(result), Field.main())

    def is_valid(self, hash_transition):
        if hash_transition in self.hash_transitions:
            return Field.main().one()
        else:
            return Field.main().zero()

    def prove(self, start_node, end_node, nonce, proof:ProofStream, path=None):
        if path is None:
            execution, call_stack, return_stack = self.load_trace_from_file("/Users/jglez2330/Library/Mobile Documents/com~apple~CloudDocs/personal/STARK-attesttation/ZEKRA-STARK/embench-iot-applications/aha-mont64/numified_path")
            trace = execution[1:]
        else:
            trace = path

        state = []
        self.registers = 8
        #Remove nonce
        transitions = trace[1:]
        for i in range(len(transitions)-1):
            nonce = trace[0]
            curr_node = transitions[i]
            next_node = transitions[i+1]
            hash_transition = self.hash_poseidon([curr_node, next_node])
            call_stack_v = Field.main().zero()
            return_stack_v = Field.main().zero()
            valid = self.is_valid(hash_transition)
            end = Field.main().zero()

            state += [[nonce, curr_node, next_node, hash_transition, call_stack_v, return_stack_v, valid, end]]

        state += [[nonce, transitions[-1],Field.main().zero(), Field.main().zero(),Field.main().zero(), Field.main().zero(),Field.main().zero(), Field.main().one()]]
        self.cycle_num = len(state)
        return  state

    def transition_constraints(self):
        # arithmetize one round of Rescue-Prime
        variables = MPolynomial.variables(1 + 2*self.registers, self.field)
        cycle_index = variables[0]
        previous_state = variables[1:(1+self.registers)]
        next_state = variables[(1+self.registers):(1+2*self.registers)]
        air = []
        for i in range(self.registers):
            lhs = MPolynomial.constant(self.field.zero())
            for k in range(self.registers):
                if k == 0:
                    lhs += previous_state[7]
                else:
                    lhs += MPolynomial.constant(Field.main().zero())
            rhs = MPolynomial.constant(self.field.zero())
            for k in range(self.registers):
                if k == 0:
                    rhs +=next_state[0] - MPolynomial.constant(FieldElement(100, Field.main()))
                else:
                    rhs += MPolynomial.constant(Field.main().zero())

            air += [lhs-rhs]

        return air


    def boundary_constrains(self, nonce, start, end):
        constraints = []

        #At start nonce is at the beggingin of the execution trace
        constraints += [(0, 0, nonce)]

        #Second element should be the start of the execution
        constraints += [(0, 1, start)]
        zero = Field.main().zero()
        #Last element should be the end of the execution trace
        constraints += [(self.cycle_num-1, 1, end)]
        #next is zero
        constraints += [(self.cycle_num-1, 2, zero)]
        #Hash is zerp
        constraints += [(self.cycle_num-1, 3, zero)]
        #Call stack is zero
        constraints += [(self.cycle_num-1, 4, zero)]
        #Call return is zero
        constraints += [(self.cycle_num-1, 5, zero)]
        #valid is zerp
        constraints += [(self.cycle_num-1, 6, zero)]
        #End is one
        constraints += [(self.cycle_num-1, 7, Field.main().one())]


        return  constraints