from algebra import FieldElement, Field


class Attestation:
    def __init__(self, cfg):
        self.cfg = cfg
        self.max_adjacency = self.calculate_max_adjacency()
        self.num_registers = 8 + self.max_adjacency
        self.field = Field.main()
        self.start = self.field.zero()
        self.end = self.field.zero()
        self.nonce = self.field.zero()

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
        #[nonce, current, next, neighbour1, neighbour2, neighbour3, neighbour4, ..., neighbourN, call_stack, call, return]
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
            state += [[nonce, current_node, next_node ] + neighbours + [call_stack_v, call, ret]]
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
        state += [[nonce, current_node, next_node ] + neighbours + [call_stack_v, call, ret]]


        return state

    def get_padded_neighbours(self, cfg, node, max_adjacency):
        neighbours = cfg[node.value]
        if len(neighbours) < max_adjacency:
            neighbours += [0] * (max_adjacency - len(neighbours))
        return neighbours[:max_adjacency]
