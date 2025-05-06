
from hashlib import blake2b

from algebra import FieldElement, Field


#This function gets a cfg and get all the transition on a hash
#i,e H(a,b) a->b
def get_list_hash_transitions(cfg):
    transitions = set()
    for src in cfg:
        dests = cfg[src]
        for dest in dests:
            transitions.add((src, dest))
    hash_transitions = []
    for transition in transitions:
        transition_bytes = str(transition).encode("UTF-8")
        hash_transitions.append(blake2b(transition_bytes).hexdigest())
    hash_transitions = [FieldElement(int.from_bytes(bytes(hash_transition, "UTF-8")), Field.main()) for hash_transition in hash_transitions]
    return hash_transitions

#This functions gets the adjlist hashed
def get_adjlist_hash(cfg):
    hash_cfg = {}
    for src in cfg:
        src_hash_bytes = blake2b(str(src).encode("UTF-8")).hexdigest()
        src_hash = FieldElement(int.from_bytes(bytes(src_hash_bytes, "UTF-8")), Field.main())
        dests = cfg[src]
        hash_cfg[src_hash.value] = []
        for dest in dests:
            dest_bytes = blake2b(str(dest).encode("UTF-8")).hexdigest()
            dest_hash = FieldElement(int.from_bytes(bytes(dest_bytes, "UTF-8")), Field.main())
            hash_cfg[src_hash.value].append(dest_hash.value)
    return hash_cfg







