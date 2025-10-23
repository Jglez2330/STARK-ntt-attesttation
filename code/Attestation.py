from networkx.classes import neighbors

from algebra import FieldElement, Field
from multivariate import MPolynomial


class Attestation:
    def __init__(self, cfg):
        self.cfg = cfg
        self.max_adjacency = self.calculate_max_adjacency()
        self.num_registers = 7 + self.max_adjacency
        self.field = Field.main()
        self.start = self.field.zero()
        self.end = self.field.zero()
        self.nonce = self.field.zero()
        self.num_cycles = 0

    def calculate_max_adjacency(self):
        max_adjacency = 0
        for node in self.cfg:
            if len(self.cfg[node]) > max_adjacency:
                max_adjacency = len(self.cfg[node])
        return max_adjacency
    def calculate_max_node_value(self):
        max_node_value = 0
        for node in self.cfg:
            if node > max_node_value:
                max_node_value = node
        self.max_node_value = FieldElement(max_node_value, self.field)
        return max_node_value + 1

    def trace(self, nonce, start, end, execution, add_false_path=False):
        self.start = start
        self.end = end
        self.nonce = nonce
        self.execution = execution
        state = []
        stack = []
        call = self.field.zero()
        ret  = self.field.zero()
        #Create first state
        state += [[self.field.zero(), self.field.zero(), self.field.zero()] + [self.field.zero()] * self.max_adjacency + [self.field.zero(), self.field.zero(), self.field.zero(), self.field.one()]]

        initial = self.field.zero()
        end_node = self.field.zero()
        #[nonce, current, next, neighbour1, neighbour2, neighbour3, neighbour4, ..., neighbourN, call_stack, call, return, initial, end]
        for i in range(len(execution)-1):
            #Get the current node
            current_node = execution[i]["dest"]
            #Get the next node
            next_node = execution[i+1]["dest"]
            #Get the neighbours of the current node
            neighbours = self.get_padded_neighbours(self.cfg, current_node, self.max_adjacency)
            #Shadow stack
            if len(stack) == 0:
                call_stack_v = self.field.zero()
            else:
                call_stack_v = stack[0]

            if execution[i]["type"] == "call":
                stack = [ execution[i]["return"]] + stack
                call_stack_v = stack[0]
                call = self.field.one()
            elif execution[i]["type"] == "ret":
                if len(stack) == 0:
                    ret = self.field.one()
                elif stack[0] == current_node:
                    stack = stack[1:]
                    if len(stack) == 0:
                        call_stack_v = self.field.zero()
                    else:
                        call_stack_v = stack[0]
                    ret = self.field.one()
            #Create the state
            neighbours = [FieldElement(neighbour, self.field) for neighbour in neighbours]
            state += [[nonce, current_node, next_node ] + neighbours + [call_stack_v, call, ret, initial, end]]
            #Reset call and ret
            call = self.field.zero()
            ret = self.field.zero()
        #Add the last state
        current_node = execution[-1]["dest"]
        next_node = self.field.zero()
        neighbours = [self.field.zero()] * self.max_adjacency
        call_stack_v = self.field.zero()
        if len(stack) == 0:
            call_stack_v = self.field.zero()
        else:
            call_stack_v = stack[0]

        if execution[-1]["type"] == "call":
            stack = [ execution[-1]["return"]] + stack
            call_stack_v = stack[0]
        elif execution[-1]["type"] == "ret":
            if len(stack) == 0:
                ret = self.field.one()
            elif stack[0] == current_node:
                stack = stack[1:]
                if len(stack) == 0:
                    call_stack_v = self.field.zero()
                else:
                    call_stack_v = stack[0]
        end_node = self.field.one()
        state += [[nonce, current_node, next_node ] + neighbours + [call_stack_v, call, ret, initial]]

        self.num_cycles = len(state)


        return state
    def boundary_constraints(self, nonce, start, end):
        constraints = []

        #Set everything to zero at the beginning
        # (position, register_index, value)
        for i in range(self.num_registers-1):
            constraints += [(0, i, self.field.zero())]
        constraints += [(0, self.num_registers-1, self.field.one())]  # Set the initial state to one



        # Check if the initial nonce is correct
        constraints += [(1, 0, nonce)]
        # Check if the start node is correct
        constraints += [(1, 1, start)]
        # Check if the end node is correct
        constraints += [(self.num_cycles-1, 1, end)]

        return constraints

    def get_valid_transition_polynomial(self, next_state, neighbours):
        acc = MPolynomial.constant(self.field.one())
        for neighbour in neighbours:
            acc *= (neighbour - next_state)
        return acc



    def transition_constraints(self, omicron):
        variables = MPolynomial.variables(1 + 2*self.num_registers, self.field)
        cycle_index = variables[0]
        previous_state = variables[1:(1+self.num_registers)]
        next_state = variables[(1+self.num_registers):(1+2*self.num_registers)]
        neighbor_start_index = 3
        call_stack_index = neighbor_start_index + self.max_adjacency
        air = []
        field = self.field
        # Check that the transition was performed correctly
        lhs = previous_state[2]
        rhs = next_state[1]

        #Check that is not the initial state
        initial_pol = MPolynomial.constant(self.field.one()) - previous_state[-1]
        air += [(lhs-rhs)*(initial_pol)]

        #Check valid next state transition (forward)
        current_neighbours = previous_state[neighbor_start_index:neighbor_start_index+self.max_adjacency]
        next_node = previous_state[2]
        valid_next_state = self.get_valid_transition_polynomial(next_node, current_neighbours)
        #Check that is not the initial state
        initial_pol = MPolynomial.constant(self.field.one()) - previous_state[-1]
        air += [valid_next_state*(initial_pol)]

        #Check stack consistency (backwards)
        lhs = previous_state[call_stack_index] * next_state[-2]
        rhs = previous_state[2] * next_state[-2]
        air += [lhs-rhs]


        return air


    def get_padded_neighbours(self, cfg, node, max_adjacency):
        neighbours = cfg[node.value]
        if len(neighbours) < max_adjacency:
            neighbours += [0] * (max_adjacency - len(neighbours))
        return neighbours[:max_adjacency]
