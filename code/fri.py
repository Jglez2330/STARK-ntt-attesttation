from algebra import *
from merkle import *
from ip import *
from ntt import *
from binascii import hexlify, unhexlify
import math
from hashlib import blake2b

from univariate import *

class Fri:
    def __init__( self, domain, field):
        self.field = field
        self.domain = domain


        assert(self.num_rounds() >= 1), "cannot do FRI with less than one round"

    def num_rounds( self ):
        codeword_length = self.domain_length
        num_rounds = 0
        while codeword_length > self.expansion_factor and 4*self.num_colinearity_tests < codeword_length:
            codeword_length /= 2
            num_rounds += 1
        return num_rounds

    def sample_index( byte_array, size ):
        acc = 0
        for b in byte_array:
            acc = (acc << 8) ^ int(b)
        return acc % size

    def sample_indices( self, seed, size, reduced_size, number ):
        assert(number <= reduced_size), f"cannot sample more indices than available in last codeword; requested: {number}, available: {reduced_size}"
        assert(number <= 2*reduced_size), "not enough entropy in indices wrt last codeword"

        indices = []
        reduced_indices = []
        counter = 0
        while len(indices) < number:
            index = Fri.sample_index(blake2b(seed + bytes(counter)).digest(), size)
            reduced_index = index % reduced_size
            counter += 1
            if reduced_index not in reduced_indices:
                indices += [index]
                reduced_indices += [reduced_index]

        return indices

    def next_fri_domain_test(self, fri_domain):
        return [x^2 for x in fri_domain[:len(fri_domain) // 2]]
    def next_fri_domain(self, domain):
        return [x^2 for x in domain[:len(domain) // 2]]

    def next_fri_polynomial(self, poly:Polynomial, beta:FieldElement) -> Polynomial:
        odd_coef = poly.coefficients[1::2]
        even_coef = poly.coefficients[::2]
        odd = beta * Polynomial(odd_coef)
        even = Polynomial(even_coef)
        return odd + even
    def next_fri_layer(self, domain, codeword, beta):
        next_poly = self.next_fri_polynomial(cp, beta)
        next_dom = self.next_fri_domain(domain)
        next_layer = next_poly.evaluate_domain(next_dom)
        return next_poly, next_dom, next_layer
    def commit( self, domain:list[FieldElement], cp_eval:list[FieldElement],proof:ProofStream):
        one = self.field.one()
        two = FieldElement(2, self.field)
        fri_domains = [domain]
        fri_layers = [cp_eval]
        cp_merkle = Merkle.commit(cp_eval)
        fri_merkles = [cp_merkle]

        proof.push(domain)
        proof.push(cp_eval)
        proof.push(cp_merkle)

        while len(fri_layers[-1]) > 0:
            beta = self.field.sample(proof.serialize())
            next_domain, next_layer = self.next_fri_layer(fri_domains[-1], fri_layers[-1], beta)
            #print(f'next_len fri layer: {len(next_layer)}')
            proof.push(next_domain)
            proof.push(next_layer)
            proof.push(Merkle.commit(next_layer))

            fri_domains.append(next_domain)
            fri_layers.append(next_layer)
            fri_merkles.append(Merkle.commit(next_layer))
        return fri_layers
    def decommit_on_fri(self, idx, fri_polys:list[Polynomial], fri_domains:list[list[FieldElement]], fri_layers, fri_merkles:list):
        assert len(fri_layers) == len(fri_merkles), f'layers size should be same as merkles size'
        res = []
        i = 0
        for layer, merkle in zip(fri_layers[:-1], fri_merkles[:-1]):
            length = len(layer)
            idx = idx % length
            sib_idx = (idx + length // 2) % length
            assert len(layer) == len(fri_domains[i])
            assert layer[idx] == fri_polys[i].evaluate(fri_domains[i][idx])
            assert layer[sib_idx] == fri_polys[i].evaluate(-fri_domains[i][idx])
            res.append(layer[idx])
            res.append(merkle.get_authentication_path(idx))
            res.append(layer[sib_idx])
            res.append(merkle.get_authentication_path(sib_idx))
            i = i+1
        res.append(fri_layers[-1][0])
        return res
    def decommit_on_query(self, idx, f_eval, f_merkle):
        assert idx + 8 < len(f_eval), f'idx should be less than len(f_eval) - 8'
        res = []
        res.append(f_eval[idx])
        res.append(f_merkle.get_authentication_path(idx))
        res.append(f_eval[idx+8])
        res.append(f_merkle.get_authentication_path(idx+8))
        return res


    def query( self, current_codeword, next_codeword, c_indices, proof_stream ):
        # infer a and b indices
        a_indices = [index for index in c_indices]
        b_indices = [index + len(current_codeword)//2 for index in c_indices]

        # reveal leafs
        for s in range(self.num_colinearity_tests):
            proof_stream.push((current_codeword[a_indices[s]], current_codeword[b_indices[s]], next_codeword[c_indices[s]]))

        # reveal authentication paths
        for s in range(self.num_colinearity_tests):
            proof_stream.push(Merkle.open(a_indices[s], current_codeword))
            proof_stream.push(Merkle.open(b_indices[s], current_codeword))
            proof_stream.push(Merkle.open(c_indices[s], next_codeword))

        return a_indices + b_indices

    def prove( self, codeword, proof_stream ):
        assert(self.domain_length == len(codeword)), "initial codeword length does not match length of initial codeword"

        # commit phase
        codewords = self.commit(codeword, proof_stream)

        # get indices
        top_level_indices = self.sample_indices(proof_stream.prover_fiat_shamir(), len(codewords[0])//2, len(codewords[-1]), self.num_colinearity_tests)
        indices = [index for index in top_level_indices]

        # query phase
        for i in range(len(codewords)-1):
            indices = [index % (len(codewords[i])//2) for index in indices] # fold
            self.query(codewords[i], codewords[i+1], indices, proof_stream)

        return top_level_indices

    def verify( self, proof_stream, polynomial_values ):
        omega = self.omega
        offset = self.offset

        # extract all roots and alphas
        roots = []
        alphas = []
        for r in range(self.num_rounds()):
            roots += [proof_stream.pull()]
            alphas += [self.field.sample(proof_stream.verifier_fiat_shamir())]

        # extract last codeword
        last_codeword = proof_stream.pull()

        # check if it matches the given root
        if roots[-1] != Merkle.commit(last_codeword):
            print("last codeword is not well formed")
            return False

        # check if it is low degree
        degree = (len(last_codeword) // self.expansion_factor) - 1
        last_omega = omega
        last_offset = offset
        for r in range(self.num_rounds()-1):
            last_omega = last_omega^2
            last_offset = last_offset^2

        # assert that last_omega has the right order
        assert(last_omega.inverse() == last_omega^(len(last_codeword)-1)), "omega does not have right order"

        # compute interpolant
        last_domain = [last_offset * (last_omega^i) for i in range(len(last_codeword))]
        poly = Polynomial.interpolate_domain(last_domain, last_codeword)
        #coefficients = intt(last_omega, last_codeword)
        #poly = Polynomial(coefficients).scale(last_offset.inverse())

        # verify by  evaluating
        assert(poly.evaluate_domain(last_domain) == last_codeword), "re-evaluated codeword does not match original!"
        if poly.degree() > degree:
            print("last codeword does not correspond to polynomial of low enough degree")
            print("observed degree:", poly.degree())
            print("but should be:", degree)
            return False

        # get indices
        top_level_indices = self.sample_indices(proof_stream.verifier_fiat_shamir(), self.domain_length >> 1, self.domain_length >> (self.num_rounds()-1), self.num_colinearity_tests)

        # for every round, check consistency of subsequent layers
        for r in range(0, self.num_rounds()-1):

            # fold c indices
            c_indices = [index % (self.domain_length >> (r+1)) for index in top_level_indices]

            # infer a and b indices
            a_indices = [index for index in c_indices]
            b_indices = [index + (self.domain_length >> (r+1)) for index in a_indices]

            # read values and check colinearity
            aa = []
            bb = []
            cc = []
            for s in range(self.num_colinearity_tests):
                (ay, by, cy) = proof_stream.pull()
                aa += [ay]
                bb += [by]
                cc += [cy]

                # record top-layer values for later verification
                if r == 0:
                    polynomial_values += [(a_indices[s], ay), (b_indices[s], by)]
                
                # colinearity check
                ax = offset * (omega^a_indices[s])
                bx = offset * (omega^b_indices[s])
                cx = alphas[r]
                if test_colinearity([(ax, ay), (bx, by), (cx, cy)]) == False:
                    print("colinearity check failure")
                    return False

            # verify authentication paths
            for i in range(self.num_colinearity_tests):
                path = proof_stream.pull()
                if Merkle.verify(roots[r], a_indices[i], path, aa[i]) == False:
                    print("merkle authentication path verification fails for aa")
                    return False
                path = proof_stream.pull()
                if Merkle.verify(roots[r], b_indices[i], path, bb[i]) == False:
                    print("merkle authentication path verification fails for bb")
                    return False
                path = proof_stream.pull()
                if Merkle.verify(roots[r+1], c_indices[i], path, cc[i]) == False:
                    print("merkle authentication path verification fails for cc")
                    return False

            # square omega and offset to prepare for next round
            omega = omega^2
            offset = offset^2

        # all checks passed
        return True

