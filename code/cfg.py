
from hashlib import blake2b

from algebra import FieldElement, Field

# Example of a Control Flow Graph (CFG) structure:
# cfg = {0: [1, 2], 1: [3], 2: [4], 3: [5], 4: [], 5:[]}
#
# ASCII Diagram of this CFG:
#
#      +---+
#      | 0 |
#      +---+
#       / \
#      /   \
#     v     v
#  +---+   +---+
#  | 1 |   | 2 |
#  +---+   +---+
#    |       |
#    v       v
#  +---+   +---+
#  | 3 |   | 4 |
#  +---+   +---+
#    |
#    v
#  +---+
#  | 5 |
#  +---+
#
# In this diagram:
# - Node 0 is the entry point with two outgoing edges to nodes 1 and 2
# - Node 1 transitions to node 3
# - Node 2 transitions to node 4
# - Node 3 transitions to node 5
# - Nodes 4 and 5 are terminal nodes (no outgoing edges)
#




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
