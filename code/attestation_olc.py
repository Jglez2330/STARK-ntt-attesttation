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
from rescue_prime import *



class Attestation:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cycle_num = 0
        self.registers = 11
        self.rp = RescuePrime()
        #self.hash_transitions = self.get_list_hash_transitions()
        self.field = Field.main()
        #self.valid_check_poly = self.valid_poly()
        self.start = Field.main().zero()
        self.end = Field.main().zero()
        self.nonce = Field.main().zero()

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
            hash_transitions.append(self.hash_trans([src, dest]))
        return hash_transitions
    def create_trace(self, path, nonce = 0, padding_value = 0, falsify_path_list=[]):
        trace = [FieldElement(nonce, Field.main())] + [FieldElement(node, Field.main()) for node in path]
        bytes_hashes = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in trace]
        random_index_to_append_falsify = random.randint(0, len(bytes_hashes)-1)
        hash_false_path = [blake2b(bytes(str(element.value).encode("UTF-8"))).hexdigest() for element in falsify_path_list]
        bytes_hashes = bytes_hashes[:random_index_to_append_falsify] + hash_false_path + bytes_hashes[random_index_to_append_falsify:]
        hash_trace = [FieldElement(int.from_bytes(bytes(bytes_hash, "UTF-8")), Field.main()) for bytes_hash in bytes_hashes]

        return hash_trace


    def execute(self, nonce, start, end, trace=None, call_stack=None, return_stack=None):
        if trace is None:
            execution, call_stack, return_stack = self.load_trace_from_file("/Users/jglez2330/Library/Mobile Documents/com~apple~CloudDocs/personal/STARK-attesttation/ZEKRA-STARK/embench-iot-applications/aha-mont64/numified_path")
            trace = execution[1:]

        return nonce + trace
    def hash_trans(self, list:list[FieldElement]):

        hash_src = self.rp.hash(list[0])
        hash_dest = self.rp.hash(list[1])
        hash = hash_src + hash_dest

        return hash

    def valid_poly(self):
        variables = MPolynomial.variables(1 + 2*self.registers, self.field)
        var = variables[1:(1+self.registers)]
        poly = var[3]
        field = Field.main()
        acc = MPolynomial.constant(field.one())
        for hash in self.hash_transitions:
            acc *= (poly-MPolynomial.constant(hash))
        return acc

    def is_valid(self, hash_transition):
        if hash_transition in self.hash_transitions:
            return Field.main().one()
        else:
            return Field.main().zero()

    def prove(self, nonce, false_path, proof:ProofStream, path=None, call_stack=None, return_stack=None):
        execution = {}
        if path is None:
            return None
        else:
            execution = path
        state = []
        self.registers = 11
        self.start = FieldElement(int(execution["start"]), Field.main())
        self.end = FieldElement(int(execution["end"]), Field.main())
        #Remove nonce
        transitions = execution["path"]
        stack = []
        for i in range(len(transitions)-1):
            nonce = nonce
            curr_node = FieldElement(int(transitions[i]["dest"]), Field.main())
            next_node = FieldElement(int(transitions[i+1]["dest"]), Field.main())
            hash_transition = self.hash_trans([curr_node, next_node])


            valid = Field.main().one()
            end = Field.main().zero()
            call = Field.main().zero()
            ret = Field.main().zero()
            hash_src = self.rp.hash(curr_node)
            hash_dest = self.rp.hash(next_node)
            if len(stack) == 0:
                call_stack_v = Field.main().zero()
            else:
                call_stack_v = stack[0]

            if transitions[i]["type"] == "call":
                stack = [ FieldElement(int(transitions[i]["return"]), Field.main())] + stack
                call_stack_v = stack[0]
                call = Field.main().one()
            elif transitions[i]["type"] == "ret":
                if len(stack) == 0:
                    ret = Field.main().one()
                elif stack[0] == curr_node:
                    stack = stack[1:]
                    if len(stack) == 0:
                        call_stack_v = Field.main().zero()
                    else:
                        call_stack_v = stack[0]
                    ret = Field.main().one()

            state += [[nonce, curr_node, next_node, hash_transition, call_stack_v, valid, end, hash_src, hash_dest, call, ret]]
        if false_path:
            random_len = random.randint(0, 10)
            for i in range(random_len):
                nonce = Field.main().zero()
                curr_node = FieldElement(800, Field.main())
                next_node = FieldElement(800, Field.main())
                hash_transition = self.hash_trans([curr_node, next_node])
                valid = Field.main().zero()
                end = Field.main().zero()
                call = Field.main().zero()
                ret = Field.main().zero()
                hash_src = self.rp.hash(curr_node)
                hash_dest = self.rp.hash(next_node)
                if len(stack) == 0:
                    call_stack_v = Field.main().zero()
                else:
                    call_stack_v = stack[0]
                state += [[nonce, curr_node, next_node, hash_transition, call_stack_v, valid, end, hash_src, hash_dest, call, ret]]

        state += [[nonce, FieldElement(int(transitions[-1]["dest"]), Field.main()),Field.main().zero(), Field.main().zero(),Field.main().zero(), Field.main().zero(),Field.main().zero(), Field.main().one(), Field.main().zero(), Field.main().zero(), Field.main().zero()]]
        self.cycle_num = len(state)
        return  state

    def polynomial_digest(self):
        field = Field.main()
        X = Polynomial([field.zero(), field.one()])
        acc = Polynomial([field.one()])
        for hash in self.hash_transitions:
            acc *= (X-hash)
        return acc
    def round_constants_polynomials( self, omicron ):
        first_step_constants = []
        for i in range(2):
            N = 64
            domain = [omicron^r for r in range(0, N)]
            values = [self.round_constants[2*r*2+i] for r in range(0, N)]
            univariate = Polynomial.interpolate_domain(domain, values)
            multivariate = MPolynomial.lift(univariate, 0)
            first_step_constants += [multivariate]
        second_step_constants = []
        for i in range(self.m):
            domain = [omicron^r for r in range(0, self.N)]
            values = [self.field.zero()] * self.N
            #for r in range(self.N):
            #    print("len(round_constants):", len(self.round_constants), " but grabbing index:", 2*r*self.m+self.m+i, "for r=", r, "for m=", self.m, "for i=", i)
            #    values[r] = self.round_constants[2*r*self.m + self.m + i]
            values = [self.round_constants[2*r*self.m+self.m+i] for r in range(self.N)]
            univariate = Polynomial.interpolate_domain(domain, values)
            multivariate = MPolynomial.lift(univariate, 0)
            second_step_constants += [multivariate]

        return first_step_constants, second_step_constants

    def transition_constraints(self, omicron):
        # arithmetize one round of Rescue-Prime
        variables = MPolynomial.variables(1 + 2*self.registers, self.field)
        cycle_index = variables[0]
        previous_state = variables[1:(1+self.registers)]
        next_state = variables[(1+self.registers):(1+2*self.registers)]
        air = []
        field = self.field
        for i in range(self.registers):
            #Default values
            lhs = MPolynomial.constant(self.field.zero())
            rhs = MPolynomial.constant(self.field.zero())
            if i == 1:
                lhs = previous_state[2]
                rhs = next_state[1]
                air += [lhs-rhs]
            #Check correct digest
            elif i == 3:
                lhs = previous_state[3]
                rhs = previous_state[7] + previous_state[8]
                air += [lhs-rhs]
            #Check stack
            elif i == 4:
                lhs = previous_state[4] * next_state[10]
                rhs = previous_state[2] * next_state[10]
                air += [lhs-rhs]
            #Check valid transition
            elif i == 5:
                #Check if the hash is one
                lhs = (MPolynomial.constant(field.one())  - previous_state[5])
                rhs = MPolynomial.constant(field.zero())
                air += [rhs-lhs]

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
        constraints += [(self.cycle_num-1, 8, Field.main().zero())]
        constraints += [(self.cycle_num-1, 9, Field.main().zero())]
        #Final values should be zeros
        constraints += [(self.cycle_num-1, 10, zero)]


        return  constraints