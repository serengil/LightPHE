# built-in dependencies
import random
import math
from typing import Optional, List, Tuple, Union, Callable

# 3rd party dependencies
import sympy

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/DamgardGeislerKroigaard.py")


class DamgardGeislerKroigaard(Homomorphic):
    """
    Damgard-Geisler-Kroigaard (DGK) algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    Messages live in Z_u for a deliberately small prime u (up to 32 bits), which keeps
    ciphertexts short and decryption fast. So, it is a good fit for small values such as
    counters, votes or bits of a secure comparison. Results that exceed this space wrap
    around, so operations producing large values (e.g. encrypted dot products on float
    tensors) are not suitable for it.
    It is a building block of secure comparison protocols, which underlie privacy-preserving
    machine learning tasks such as private decision tree evaluation and encrypted argmax.
    All of them are supported here in the semi-honest model, between a client holding
    the private key and a server.
    Ref: Damgard, I., Geisler, M., Kroigaard, M. (2007). Efficient and Secure Comparison
        for On-Line Auctions. ACISP 2007. Correction: https://eprint.iacr.org/2008/321
    Ref: Tai, R. K. H., Ma, J. P. K., Zhao, Y., Chow, S. S. M. (2017). Privacy-Preserving
        Decision Trees Evaluation via Linear Functions. ESORICS 2017.
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "g", "h", "u", "t"],
        "private_key": ["p", "v_p"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        max_tries: int = 10000,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
            max_tries (int): maximum attempts to generate keys
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 1024, max_tries=max_tries
        )
        self.plaintext_modulo = self.keys["public_key"]["u"]
        self.ciphertext_modulo = self.keys["public_key"]["n"]

        # baby-step giant-step lookup table, built once on first decryption
        self.__baby_steps: Optional[dict] = None

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Damgard-Geisler-Kroigaard cryptosystem
        Args:
            key_size (int): key size in bits
            max_tries (int): maximum number of tries to generate keys
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        prime_size = key_size // 2

        # u is the plaintext space. it is kept small because decryption requires
        # solving a discrete logarithm in a subgroup of order u.
        u_size = min(32, max(4, key_size // 16))

        # v_p and v_q are the orders of the randomizer subgroup. 160 bits in the paper.
        # at least 6 bits so that there are enough primes to pick distinct u, v_p and v_q
        t = min(160, max(6, key_size // 6))

        # the rest of p and q is filled with a random part
        r_size = prime_size - u_size - t - 1
        if r_size < 2:
            raise ValueError(
                f"Key size {key_size} is too small for Damgard-Geisler-Kroigaard"
            )

        u = sympy.randprime(2 ** (u_size - 1), 2**u_size)

        v_p = sympy.randprime(2 ** (t - 1), 2**t)
        while v_p == u:
            v_p = sympy.randprime(2 ** (t - 1), 2**t)

        v_q = sympy.randprime(2 ** (t - 1), 2**t)
        while v_q in (u, v_p):
            v_q = sympy.randprime(2 ** (t - 1), 2**t)

        # picking primes p and q such that u * v_p divides p - 1 and u * v_q divides q - 1
        p = self.__find_prime(u=u, v=v_p, r_size=r_size, max_tries=max_tries)
        q = self.__find_prime(u=u, v=v_q, r_size=r_size, max_tries=max_tries)
        while q == p:
            q = self.__find_prime(u=u, v=v_q, r_size=r_size, max_tries=max_tries)

        n = p * q

        # g has order u * v_p * v_q, and h has order v_p * v_q in Z_n*.
        # they are built in Z_p* and Z_q* separately, and then combined with CRT
        g_p = self.__find_element_of_order(p=p, factors=[u, v_p], max_tries=max_tries)
        g_q = self.__find_element_of_order(p=q, factors=[u, v_q], max_tries=max_tries)
        h_p = self.__find_element_of_order(p=p, factors=[v_p], max_tries=max_tries)
        h_q = self.__find_element_of_order(p=q, factors=[v_q], max_tries=max_tries)

        g = self.__crt(a_p=g_p, a_q=g_q, p=p, q=q)
        h = self.__crt(a_p=h_p, a_q=h_q, p=p, q=q)

        keys["public_key"]["n"] = n
        keys["public_key"]["g"] = g
        keys["public_key"]["h"] = h
        keys["public_key"]["u"] = u
        keys["public_key"]["t"] = t

        keys["private_key"]["p"] = p
        keys["private_key"]["q"] = q
        keys["private_key"]["v_p"] = v_p
        keys["private_key"]["v_q"] = v_q

        return keys

    def generate_random_key(self) -> int:
        """
        Damgard-Geisler-Kroigaard requires to generate one-time random key per encryption.
            In the paper, it is a 2.5t bit random integer.
        Returns:
            random key (int): one time random key for encryption
        """
        t = self.keys["public_key"]["t"]
        return random.randint(1, 2 ** int(2.5 * t))

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with Damgard-Geisler-Kroigaard
        Args:
            plaintext (int): message to encrypt in [0, u)
            random_key (int): Damgard-Geisler-Kroigaard requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        h = self.keys["public_key"]["h"]
        r = random_key or self.generate_random_key()

        if plaintext >= self.plaintext_modulo:
            plaintext = plaintext % self.plaintext_modulo
            logger.debug(
                f"Damgard-Geisler-Kroigaard can encrypt messages [0, {self.plaintext_modulo}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        return (pow(g, plaintext, n) * pow(h, r, n)) % n

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a given ciphertext with Damgard-Geisler-Kroigaard
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        p = self.keys["private_key"]["p"]
        v_p = self.keys["private_key"]["v_p"]
        g = self.keys["public_key"]["g"]
        u = self.keys["public_key"]["u"]

        # c^v_p = (g^v_p)^m mod p because h^v_p = 1 mod p. g^v_p has order u in Z_p*
        # so m is the discrete logarithm of c^v_p in a small subgroup of order u.
        z = pow(ciphertext, v_p, p)
        base = pow(g, v_p, p)

        # baby-step giant-step
        step = math.isqrt(u) + 1
        if self.__baby_steps is None:
            self.__baby_steps = {}
            value = 1
            for j in range(step):
                self.__baby_steps.setdefault(value, j)
                value = (value * base) % p

        giant = pow(base, -step, p)
        for i in range(step):
            j = self.__baby_steps.get(z)
            if j is not None:
                return (i * step + j) % u
            z = (z * giant) % p

        raise ValueError("Damgard-Geisler-Kroigaard ciphertext cannot be decrypted")

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (int): 1st ciphertext created with Damgard-Geisler-Kroigaard
            ciphertext2 (int): 2nd ciphertext created with Damgard-Geisler-Kroigaard
        Returns:
            ciphertext3 (int): 3rd ciphertext created with Damgard-Geisler-Kroigaard
        """
        n = self.keys["public_key"]["n"]
        return (ciphertext1 * ciphertext2) % n

    def multiply_by_constant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Args:
            ciphertext (int): ciphertext created with Damgard-Geisler-Kroigaard
            constant (int): known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Damgard-Geisler-Kroigaard
        """
        n = self.keys["public_key"]["n"]

        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Damgard-Geisler-Kroigaard can encrypt messages [0, {self.plaintext_modulo}). "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )

        return pow(ciphertext, constant, n)

    def reencrypt(self, ciphertext: int) -> int:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (int): given ciphertext
        Returns:
            new ciphertext (int): different ciphertext for same plaintext
        """
        neutral_element = 0
        neutral_encrypted = self.encrypt(plaintext=neutral_element)
        return self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    def is_zero(self, ciphertext: int) -> bool:
        """
        Check a ciphertext encrypts 0 without solving the discrete logarithm.
            c^v_p = (g^v_p)^m mod p and g^v_p has order u, so it is 1 if and only if m = 0.
        Args:
            ciphertext (int): encrypted message
        Returns:
            result (bool): True if ciphertext encrypts 0
        """
        p = self.keys["private_key"]["p"]
        v_p = self.keys["private_key"]["v_p"]
        return pow(ciphertext, v_p, p) == 1

    def encrypt_comparison_input(self, value: int, bit_length: int) -> List[int]:
        """
        Encrypt bits of a value to be compared with a value of the server.
            This is the 1st step of secure comparison and runs on client side.
        Args:
            value (int): client's value in [0, 2^bit_length)
            bit_length (int): number of bits of compared values
        Returns:
            encrypted bits (list of int): least significant bit first
        """
        self.__validate_comparison_input(value=value, bit_length=bit_length)
        return [self.encrypt(plaintext=(value >> i) & 1) for i in range(bit_length)]

    def evaluate_comparison(self, encrypted_input: List[int], value: int) -> List[int]:
        """
        Compare client's encrypted value x with server's value y.
            This is the 2nd step of secure comparison and runs on server side.
            Private key is not required, and server learns nothing about x.
        Args:
            encrypted_input (list of int): output of encrypt_comparison_input
            value (int): server's value y in [0, 2^bit_length)
        Returns:
            encrypted result (list of int): to be sent to the client
        """
        return self.__blind_comparison(
            encrypted_bits=encrypted_input, value=value, flip=0
        )

    def decrypt_comparison(self, encrypted_result: List[int]) -> bool:
        """
        Restore the result of secure comparison.
            This is the 3rd step of secure comparison and runs on client side.
            Client learns only whether x <= y, but not y.
        Args:
            encrypted_result (list of int): output of evaluate_comparison
        Returns:
            result (bool): True if x <= y
        """
        return any(self.is_zero(c) for c in encrypted_result)

    def encrypt_decision_tree_features(
        self, features: List[int], bit_length: int
    ) -> List[List[int]]:
        """
        Encrypt features of a client to be evaluated in server's decision tree.
            This is the 1st step of private decision tree evaluation and runs on client side.
        Args:
            features (list of int): client's features each in [0, 2^bit_length)
            bit_length (int): number of bits of features and thresholds
        Returns:
            encrypted features (list of list of int): to be sent to the server
        """
        return [
            self.encrypt_comparison_input(value=feature, bit_length=bit_length)
            for feature in features
        ]

    def evaluate_decision_tree_comparisons(
        self, tree: Union[int, tuple], encrypted_features: List[List[int]]
    ) -> Tuple[List[List[int]], dict]:
        """
        Compare encrypted features with thresholds of all decision nodes.
            This is the 2nd step of private decision tree evaluation and runs on server side.
            Each comparison is randomly flipped, so client cannot learn the path.
        Args:
            tree (int or tuple): leaf label (int) or decision node
                (feature_index, threshold, tree_if_less_or_equal, tree_if_greater)
            encrypted_features (list of list of int): output of encrypt_decision_tree_input
        Returns:
            encrypted comparisons (list of list of int): to be sent to the client
            server state (dict): must be kept secret on server side for the last step
        """
        nodes = self.__collect_nodes(tree=tree)
        flips = [random.randint(0, 1) for _ in nodes]

        encrypted_comparisons = []
        for (feature_index, threshold), flip in zip(nodes, flips):
            if not 0 <= feature_index < len(encrypted_features):
                raise ValueError(f"Feature index {feature_index} does not exist")
            encrypted_comparisons.append(
                self.__blind_comparison(
                    encrypted_bits=encrypted_features[feature_index],
                    value=threshold,
                    flip=flip,
                )
            )

        return encrypted_comparisons, {"tree": tree, "flips": flips}

    def answer_decision_tree_comparisons(
        self, encrypted_comparisons: List[List[int]]
    ) -> List[int]:
        """
        Answer the flipped comparisons of the server in encrypted form.
            This is the 3rd step of private decision tree evaluation and runs on client side.
        Args:
            encrypted_comparisons (list of list of int): output of
                evaluate_decision_tree_comparisons
        Returns:
            encrypted answers (list of int): to be sent to the server
        """
        return [
            self.encrypt(plaintext=int(self.decrypt_comparison(comparison)))
            for comparison in encrypted_comparisons
        ]

    def evaluate_decision_tree_leaves(
        self, server_state: dict, encrypted_answers: List[int]
    ) -> List[Tuple[int, int]]:
        """
        Find the reached leaf in encrypted form. Path cost of a leaf is the number of wrong
            decisions on its path, so only the reached leaf has cost 0.
            This is the 4th step of private decision tree evaluation and runs on server side.
        Args:
            server_state (dict): output of evaluate_decision_tree_comparisons
            encrypted_answers (list of int): output of answer_decision_tree_comparisons
        Returns:
            encrypted leaves (list of tuple of int): to be sent to the client
        """
        u = self.plaintext_modulo
        tree = server_state["tree"]
        flips = server_state["flips"]

        # path cost is at most the depth of the tree, so it must not wrap around u
        if len(flips) >= u:
            raise ValueError(f"Decision tree must have less than {u} decision nodes")

        if len(encrypted_answers) != len(flips):
            raise ValueError(
                f"Expected {len(flips)} answers but got {len(encrypted_answers)}"
            )

        # remove the random flip, so b = 1 if feature <= threshold
        encrypted_decisions = [
            answer if flip == 0 else self.__negate_bit(answer)
            for answer, flip in zip(encrypted_answers, flips)
        ]

        # path cost of each leaf. going left is wrong if b = 0, going right is wrong if b = 1
        leaves: List[Tuple[int, int]] = []
        node_index = 0

        def traverse(subtree: Union[int, tuple], cost: int) -> None:
            nonlocal node_index
            if isinstance(subtree, int):
                if not 0 <= subtree < u:
                    raise ValueError(f"Leaf labels must be in [0, {u}) but got {subtree}")
                leaves.append((cost, subtree))
                return
            b = encrypted_decisions[node_index]
            node_index += 1
            traverse(subtree[2], self.add(cost, self.__negate_bit(b)))
            traverse(subtree[3], self.add(cost, b))

        traverse(tree, self.encrypt(plaintext=0))

        # for each leaf, client receives (r1 * cost, r2 * cost + label). only the reached
        # leaf has cost 0, others look random to the client.
        encrypted_leaves = []
        for cost, label in leaves:
            r1 = random.randint(1, u - 1)
            r2 = random.randint(1, u - 1)
            masked_cost = self.reencrypt(self.multiply_by_constant(cost, r1))
            masked_label = self.add(
                self.multiply_by_constant(cost, r2), self.encrypt(plaintext=label)
            )
            encrypted_leaves.append((masked_cost, masked_label))

        random.shuffle(encrypted_leaves)
        return encrypted_leaves

    def decrypt_decision_tree_output(
        self, encrypted_leaves: List[Tuple[int, int]]
    ) -> int:
        """
        Restore the label of the reached leaf.
            This is the last step of private decision tree evaluation and runs on client side.
        Args:
            encrypted_leaves (list of tuple of int): output of evaluate_decision_tree_leaves
        Returns:
            label (int): label of the reached leaf
        """
        for masked_cost, masked_label in encrypted_leaves:
            if self.is_zero(masked_cost):
                return self.decrypt(masked_label)
        raise ValueError("None of the leaves is reached")

    def evaluate_argmax(
        self,
        encrypted_values: List[int],
        bit_length: int,
        client: Callable[[dict], List[int]],
    ) -> int:
        """
        Find the index of the maximum of encrypted values without decrypting them.
            Runs on server side and interacts with the client (private key owner) through
            the client callable. Client learns neither the values nor the comparison results,
            and server learns nothing. Index of the first maximum is returned on ties.
        Args:
            encrypted_values (list of int): ciphertexts of values in [0, 2^bit_length)
            bit_length (int): number of bits of the values
            client (callable): sends a message to the client and returns its response,
                e.g. answer_argmax of the client's cryptosystem or a network call.
        Returns:
            encrypted index (int): ciphertext of the argmax index, to be sent to the client
        """
        u = self.plaintext_modulo

        if len(encrypted_values) == 0:
            raise ValueError("Argmax requires at least one value")

        # z = b - a + 2^bit_length must be in the plaintext space without wrapping around
        if 2 ** (bit_length + 1) >= u:
            raise ValueError(
                f"Plaintext space {u} is too small for argmax of {bit_length}-bit values. "
                "Use a larger key size or a smaller bit length."
            )

        # client's masked values are compared bit by bit, so u's bit length must fit
        self.__validate_comparison_input(value=u - 1, bit_length=u.bit_length())

        max_value = encrypted_values[0]
        max_index = self.encrypt(plaintext=0)
        for index in range(1, len(encrypted_values)):
            candidate = encrypted_values[index]
            is_greater = self.__greater_than(
                encrypted_a=candidate,
                encrypted_b=max_value,
                bit_length=bit_length,
                client=client,
            )

            # max_value += is_greater * (candidate - max_value)
            # max_index += is_greater * (index - max_index)
            value_diff = self.add(candidate, self.__negate(max_value))
            index_diff = self.add(self.encrypt(plaintext=index), self.__negate(max_index))
            value_update, index_update = self.__multiply(
                encrypted_bit=is_greater,
                encrypted_factors=[value_diff, index_diff],
                client=client,
            )
            max_value = self.add(max_value, value_update)
            max_index = self.add(max_index, index_update)

        return self.reencrypt(max_index)

    def answer_argmax(self, message: dict) -> List[int]:
        """
        Answer a message of the server during encrypted argmax. Runs on client side.
            Every value the client decrypts here is masked with a uniformly random value,
            so client learns nothing.
        Args:
            message (dict): message of the server having type and payload keys
        Returns:
            response (list of int): ciphertexts to be sent back to the server
        """
        u = self.plaintext_modulo
        message_type = message.get("type")
        payload = message.get("payload")

        if message_type == "masked_difference":
            masked = self.decrypt(payload[0])
            return self.encrypt_comparison_input(value=masked, bit_length=u.bit_length())

        if message_type == "comparisons":
            bits = [int(self.decrypt_comparison(comparison)) for comparison in payload]
            return [
                self.encrypt(plaintext=bits[0]),
                self.encrypt(plaintext=bits[1]),
                self.encrypt(plaintext=bits[0] * bits[1]),
            ]

        if message_type == "products":
            masked_bit = self.decrypt(payload[0])
            return [
                self.encrypt(plaintext=(masked_bit * self.decrypt(factor)) % u)
                for factor in payload[1:]
            ]

        raise ValueError(f"Unknown argmax message type {message_type}")

    def __greater_than(
        self,
        encrypted_a: int,
        encrypted_b: int,
        bit_length: int,
        client: Callable[[dict], List[int]],
    ) -> int:
        """
        Compute E(a > b) for encrypted a and b in [0, 2^bit_length) with the client's help.
        """
        u = self.plaintext_modulo
        offset = 2**bit_length

        # z = a - b + 2^bit_length is in [1, 2^(bit_length + 1)), and a > b iff z > 2^bit_length.
        # client receives d = z + r mod u for a uniformly random r, which reveals nothing.
        r = random.randint(0, u - 1)
        masked_difference = self.add(
            self.add(encrypted_a, self.__negate(encrypted_b)),
            self.encrypt(plaintext=(offset + r) % u),
        )
        encrypted_d_bits = client(
            {"type": "masked_difference", "payload": [self.reencrypt(masked_difference)]}
        )

        # a > b iff d is in the arc [start, end] of Z_u. if the arc does not wrap around u,
        # it is (d >= start) and (d <= end). otherwise, it is (d >= start) or (d <= end).
        start = (r + offset + 1) % u
        end = (r + 2 * offset - 1) % u
        wraps = start > end

        # each comparison gives client a bit x_i, while server keeps a bit k_i such that
        # c_i = x_i xor k_i. random flips make x_i uniformly random for the client.
        # d >= start is the negation of d <= start - 1, and always true if start = 0.
        flips = [random.randint(0, 1), random.randint(0, 1)]
        if start == 0:
            first_threshold, first_negated = u - 1, 0
        else:
            first_threshold, first_negated = start - 1, 1

        comparisons = [
            self.__blind_comparison(
                encrypted_bits=encrypted_d_bits, value=first_threshold, flip=flips[0]
            ),
            self.__blind_comparison(
                encrypted_bits=encrypted_d_bits, value=end, flip=flips[1]
            ),
        ]
        x1, x2, x1x2 = client({"type": "comparisons", "payload": comparisons})

        k1 = flips[0] ^ first_negated
        k2 = flips[1]

        # c_i = k_i + (1 - 2 k_i) x_i is linear in x_i, and so is c_1 * c_2 in x_1, x_2, x_1 x_2
        c1 = self.__linear([(x1, 1 - 2 * k1)], constant=k1)
        c2 = self.__linear([(x2, 1 - 2 * k2)], constant=k2)
        c1c2 = self.__linear(
            [
                (x1, k2 * (1 - 2 * k1)),
                (x2, k1 * (1 - 2 * k2)),
                (x1x2, (1 - 2 * k1) * (1 - 2 * k2)),
            ],
            constant=k1 * k2,
        )

        if wraps:
            # c1 or c2 = c1 + c2 - c1 * c2
            return self.add(self.add(c1, c2), self.__negate(c1c2))
        return c1c2

    def __multiply(
        self,
        encrypted_bit: int,
        encrypted_factors: List[int],
        client: Callable[[dict], List[int]],
    ) -> List[int]:
        """
        Compute E(b * f) for an encrypted b and each encrypted f with the client's help.
            Client multiplies B = b + rho and F = f + sigma, both uniformly random, and
            server restores b * f = B * F - sigma * b - rho * f - rho * sigma.
        """
        u = self.plaintext_modulo
        rho = random.randint(0, u - 1)
        sigmas = [random.randint(0, u - 1) for _ in encrypted_factors]

        masked_bit = self.add(encrypted_bit, self.encrypt(plaintext=rho))
        masked_factors = [
            self.add(factor, self.encrypt(plaintext=sigma))
            for factor, sigma in zip(encrypted_factors, sigmas)
        ]
        masked_products = client(
            {"type": "products", "payload": [masked_bit] + masked_factors}
        )

        return [
            self.__linear(
                [(masked_product, 1), (encrypted_bit, -sigma), (factor, -rho)],
                constant=-rho * sigma,
            )
            for masked_product, factor, sigma in zip(
                masked_products, encrypted_factors, sigmas
            )
        ]

    def __linear(self, terms: List[Tuple[int, int]], constant: int) -> int:
        """
        Compute E(sum(coefficient * m) + constant) for (E(m), coefficient) terms
        """
        u = self.plaintext_modulo
        result = self.encrypt(plaintext=constant % u)
        for ciphertext, coefficient in terms:
            coefficient %= u
            if coefficient != 0:
                result = self.add(
                    result, self.multiply_by_constant(ciphertext, coefficient)
                )
        return result

    def __negate(self, ciphertext: int) -> int:
        """
        Compute E(-m) from E(m)
        """
        return self.multiply_by_constant(ciphertext, self.plaintext_modulo - 1)

    def __validate_comparison_input(self, value: int, bit_length: int) -> None:
        """
        Check that a compared value fits into bit_length bits, and the comparison
            fits into the plaintext space.
        """
        if not isinstance(value, int) or not 0 <= value < 2**bit_length:
            raise ValueError(
                f"Compared values must be integers in [0, 2^{bit_length}) but got {value}"
            )

        # values are extended by one bit to break ties. intermediate values of the
        # comparison are in [-2, 3 * (bit_length + 1) - 1] and must not wrap around u.
        if 3 * (bit_length + 1) - 1 >= self.plaintext_modulo:
            raise ValueError(
                f"Plaintext space {self.plaintext_modulo} is too small to compare "
                f"{bit_length}-bit values. Use a larger key size or a smaller bit length."
            )

    def __negate_bit(self, ciphertext: int) -> int:
        """
        Compute E(1 - b) from E(b) for a bit b
        """
        u = self.plaintext_modulo
        return self.add(
            self.encrypt(plaintext=1), self.multiply_by_constant(ciphertext, u - 1)
        )

    def __blind_comparison(
        self, encrypted_bits: List[int], value: int, flip: int
    ) -> List[int]:
        """
        DGK comparison of client's encrypted x and server's plain y. Client finds a
            zero among the returned ciphertexts if and only if x <= y (flip = 0) or
            x > y (flip = 1).
        Args:
            encrypted_bits (list of int): encrypted bits of x, least significant bit first
            value (int): y
            flip (int): 0 or 1. server keeps it secret to hide the result from the client
        Returns:
            blinded ciphertexts (list of int): shuffled and re-randomized
        """
        u = self.plaintext_modulo
        bit_length = len(encrypted_bits)
        self.__validate_comparison_input(value=value, bit_length=bit_length)

        # compare 2x with 2y + 1 instead, so that x <= y if and only if 2x < 2y + 1.
        # this way, x and y are never equal and flipping the direction is consistent.
        x_bits = [self.encrypt(plaintext=0)] + list(encrypted_bits)
        y = 2 * value + 1
        y_bits = [(y >> i) & 1 for i in range(bit_length + 1)]

        # s = 1 looks for x < y, s = -1 looks for x > y
        s = 1 if flip == 0 else u - 1

        # c_i = s + x_i - y_i + 3 * sum_{j > i} (x_j xor y_j)
        # c_i = 0 only at the most significant differing bit, and only if x_i - y_i = -s
        blinded = []
        xor_sum = self.encrypt(plaintext=0)
        for i in reversed(range(bit_length + 1)):
            c = self.add(self.encrypt(plaintext=(s - y_bits[i]) % u), x_bits[i])
            c = self.add(c, self.multiply_by_constant(xor_sum, 3))

            r = random.randint(1, u - 1)
            blinded.append(self.reencrypt(self.multiply_by_constant(c, r)))

            x_xor_y = x_bits[i] if y_bits[i] == 0 else self.__negate_bit(x_bits[i])
            xor_sum = self.add(xor_sum, x_xor_y)

        random.shuffle(blinded)
        return blinded

    @staticmethod
    def __collect_nodes(tree: Union[int, tuple]) -> List[Tuple[int, int]]:
        """
        Collect (feature_index, threshold) of decision nodes in pre-order
        """
        if isinstance(tree, int):
            return []
        if not isinstance(tree, (tuple, list)) or len(tree) != 4:
            raise ValueError(
                "Decision node must be (feature_index, threshold, tree_if_less_or_equal,"
                f" tree_if_greater) but got {tree}"
            )
        feature_index, threshold, left, right = tree
        return (
            [(feature_index, threshold)]
            + DamgardGeislerKroigaard.__collect_nodes(left)
            + DamgardGeislerKroigaard.__collect_nodes(right)
        )

    @staticmethod
    def __find_prime(u: int, v: int, r_size: int, max_tries: int) -> int:
        """
        Find a prime p in the form of 2 * u * v * r + 1
        Args:
            u (int): plaintext space
            v (int): order of the randomizer subgroup
            r_size (int): bit length of the random part r
            max_tries (int): maximum number of tries
        Returns:
            p (int): prime
        """
        for _ in range(max_tries):
            r = random.randint(2 ** (r_size - 1), 2**r_size - 1)
            p = 2 * u * v * r + 1
            if sympy.isprime(p):
                return p
        raise ValueError(f"Failed to find prime p = 1 mod 2*{u}*{v} in {max_tries} tries")

    @staticmethod
    def __find_element_of_order(p: int, factors: list, max_tries: int) -> int:
        """
        Find an element of Z_p* whose order is exactly the product of given distinct primes
        Args:
            p (int): prime modulus
            factors (list of int): distinct primes each dividing p - 1
            max_tries (int): maximum number of tries
        Returns:
            element (int): element of order prod(factors)
        """
        order = math.prod(factors)
        for _ in range(max_tries):
            x = random.randint(2, p - 2)
            y = pow(x, (p - 1) // order, p)
            # order of y divides prod(factors). it is exactly that if
            # removing any prime factor does not send y to 1
            if all(pow(y, order // f, p) != 1 for f in factors):
                return y
        raise ValueError(f"Failed to find an element of order {order} in {max_tries} tries")

    @staticmethod
    def __crt(a_p: int, a_q: int, p: int, q: int) -> int:
        """
        Find x such that x = a_p mod p and x = a_q mod q
        """
        return (a_p + p * ((a_q - a_p) * pow(p, -1, q) % q)) % (p * q)
