# built-in dependencies
import math
from typing import Optional, List, Tuple, Union, Dict

# project dependencies
from lightphe.cryptosystems.DamgardJurik import DamgardJurik
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/IshaiPaskin.py")

# a decision tree node is either a leaf (int) or a decision node
# (variable_index, tree_if_0, tree_if_1)
DecisionTree = Union[int, Tuple[int, "DecisionTree", "DecisionTree"]]

DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG = (
    "Output of a decision tree can only be decrypted."
    " Homomorphic operations are not supported on it."
)


class IshaiPaskin(DamgardJurik):
    """
    Ishai-Paskin algorithm evaluates a decision tree on encrypted data.
    Client encrypts its input bits, server holding a private decision tree
    evaluates it on the encrypted input and returns an encryption of the output.
    Ciphertext size depends on the depth of the tree, not on its size.
    The paper calls these branching programs. Decision trees are their most common
    form, and trees sharing sub trees (DAGs) are supported as well.
    It is built on length flexible Damgard-Jurik: level s encrypts messages in
    Z_{n^s} into ciphertexts in Z_{n^(s+1)}, so a level s ciphertext fits into
    the plaintext space of level s+1. Each level of the tree wraps one more
    encryption layer around the result.
    It is also homomorphic with respect to the addition as Damgard-Jurik.
    Ref: Ishai, Y., Paskin, A. (2007). Evaluating Branching Programs on Encrypted Data.
        TCC 2007. https://doi.org/10.1007/978-3-540-70936-7_31
    """

    def encrypt_at_level(
        self, plaintext: int, level: int, random_key: Optional[int] = None
    ) -> int:
        """
        Encrypt a given plaintext with Damgard-Jurik at given level
        Args:
            plaintext (int): message to encrypt in Z_{n^level}
            level (int): encryption level s. ciphertext will be in Z_{n^(s+1)}
            random_key (int): one time random key co-prime to n.
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        r = random_key or self.generate_random_key()
        modulo = pow(n, level + 1)
        return (pow(g, plaintext, modulo) * pow(r, pow(n, level), modulo)) % modulo

    def decrypt_at_level(self, ciphertext: int, level: int) -> int:
        """
        Decrypt a given ciphertext with Damgard-Jurik at given level
        Args:
            ciphertext (int): encrypted message in Z_{n^(level+1)}
            level (int): encryption level s
        Returns:
            plaintext (int): restored message in Z_{n^level}
        """
        phi = self.keys["private_key"]["phi"]
        n = self.keys["public_key"]["n"]

        # randomness vanishes because the order of Z*_{n^(s+1)} is phi * n^s.
        # what remains is (1 + n)^(m * phi)
        a = pow(ciphertext, phi, pow(n, level + 1))
        m_phi = self.__dlog(a, level)
        return (m_phi * pow(phi, -1, pow(n, level))) % pow(n, level)

    def __dlog(self, a: int, level: int) -> int:
        """
        Find i such that a = (1 + n)^i mod n^(s+1) with Damgard-Jurik's recursive algorithm
        Args:
            a (int): power of 1 + n
            level (int): encryption level s
        Returns:
            i (int): discrete logarithm in Z_{n^s}
        """
        n = self.keys["public_key"]["n"]
        i = 0
        for j in range(1, level + 1):
            nj = pow(n, j)
            t1 = (a % pow(n, j + 1) - 1) // n
            t2 = i
            for k in range(2, j + 1):
                i = i - 1
                t2 = (t2 * i) % nj
                t1 = (t1 - t2 * pow(n, k - 1) * pow(math.factorial(k), -1, nj)) % nj
            i = t1
        return i

    def encrypt_decision_tree_input(self, bits: List[int], depth: int) -> List[List[int]]:
        """
        Encrypt input bits of a decision tree. Each bit is encrypted at every
            level from 1 to depth because server decides which level it needs.
        Args:
            bits (list of int): input bits x_0, x_1, ... each 0 or 1
            depth (int): maximum depth of decision trees to evaluate
        Returns:
            encrypted input (list of list of int): item [i][s - 1] is encryption of x_i at level s
        """
        if depth < 1:
            raise ValueError(f"depth must be a positive integer but it is {depth}")

        encrypted_input = []
        for bit in bits:
            if bit not in (0, 1):
                raise ValueError(f"Input must consist of bits (0 or 1) but got {bit}")
            encrypted_input.append(
                [
                    self.encrypt_at_level(plaintext=bit, level=level)
                    for level in range(1, depth + 1)
                ]
            )
        return encrypted_input

    def evaluate_decision_tree(
        self, tree: DecisionTree, encrypted_input: List[List[int]]
    ) -> Tuple[int, int]:
        """
        Evaluate a decision tree on encrypted input. Private key is not required.
        Args:
            tree (DecisionTree): leaf (int) or decision node
                (variable_index, tree_if_0, tree_if_1).
                e.g. (0, (1, 0, 1), 1) is x_0 OR x_1
            encrypted_input (list of list of int): output of encrypt_decision_tree_input
        Returns:
            output (tuple): (level, ciphertext) where ciphertext wraps level layers of
                encryption around the output of the tree
        """
        depth = len(encrypted_input[0]) if encrypted_input else 0
        memo: Dict[int, Tuple[int, int]] = {}
        level, ciphertext = self.__evaluate_node(
            tree=tree, encrypted_input=encrypted_input, depth=depth, memo=memo
        )

        if level == 0:
            # tree is a constant, still return an encrypted output
            ciphertext = self.encrypt_at_level(plaintext=ciphertext, level=1)
            level = 1

        return level, ciphertext

    def __evaluate_node(
        self,
        tree: DecisionTree,
        encrypted_input: List[List[int]],
        depth: int,
        memo: Dict[int, Tuple[int, int]],
    ) -> Tuple[int, int]:
        """
        Evaluate a node of decision tree bottom up
        Args:
            tree (DecisionTree): node to evaluate
            encrypted_input (list of list of int): output of encrypt_decision_tree_input
            depth (int): number of levels available in encrypted input
            memo (dict): already evaluated nodes to support shared sub trees
        Returns:
            result (tuple): (level, value). level 0 means plain leaf value
        """
        if isinstance(tree, int):
            return 0, tree % self.keys["public_key"]["n"]

        if not isinstance(tree, (tuple, list)) or len(tree) != 3:
            raise ValueError(
                "Decision tree node must be an int leaf or a tuple of "
                f"(variable_index, tree_if_0, tree_if_1) but got {tree}"
            )

        if id(tree) in memo:
            return memo[id(tree)]

        variable_index, tree_if_0, tree_if_1 = tree
        if not 0 <= variable_index < len(encrypted_input):
            raise ValueError(
                f"Variable index {variable_index} is out of input range "
                f"[0, {len(encrypted_input)})"
            )

        level_0, value_0 = self.__evaluate_node(
            tree_if_0, encrypted_input, depth, memo
        )
        level_1, value_1 = self.__evaluate_node(
            tree_if_1, encrypted_input, depth, memo
        )

        # bring both branches to the same level by wrapping fresh encryption layers
        level = max(level_0, level_1)
        value_0 = self.__lift(value_0, level_0, level)
        value_1 = self.__lift(value_1, level_1, level)

        # values at level l are in Z_{n^(l+1)}, which is plaintext space of level l+1.
        # E(x)^(v1 - v0) * E(v0) = E(v0 + x * (v1 - v0)) = E(v_x)
        level += 1
        if level > depth:
            raise ValueError(
                f"Decision tree is deeper than {depth} levels of encrypted input"
            )

        n = self.keys["public_key"]["n"]
        plaintext_modulo = pow(n, level)
        ciphertext_modulo = pow(n, level + 1)

        encrypted_bit = encrypted_input[variable_index][level - 1]
        difference = (value_1 - value_0) % plaintext_modulo
        ciphertext = (
            pow(encrypted_bit, difference, ciphertext_modulo)
            * self.encrypt_at_level(plaintext=value_0, level=level)
        ) % ciphertext_modulo

        memo[id(tree)] = (level, ciphertext)
        return level, ciphertext

    def __lift(self, value: int, from_level: int, to_level: int) -> int:
        """
        Wrap encryption layers around a value with fresh randomness
        Args:
            value (int): plain value (level 0) or ciphertext of from_level
            from_level (int): current level of value
            to_level (int): target level
        Returns:
            value (int): ciphertext of to_level
        """
        for level in range(from_level + 1, to_level + 1):
            value = self.encrypt_at_level(plaintext=value, level=level)
        return value

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        if not isinstance(ciphertext1, int) or not isinstance(ciphertext2, int):
            raise ValueError(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG)
        return super().add(ciphertext1=ciphertext1, ciphertext2=ciphertext2)

    def multiply_by_constant(self, ciphertext: int, constant: int) -> int:
        if not isinstance(ciphertext, int):
            raise ValueError(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG)
        return super().multiply_by_constant(ciphertext=ciphertext, constant=constant)

    def reencrypt(self, ciphertext: int) -> int:
        if not isinstance(ciphertext, int):
            raise ValueError(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG)
        return super().reencrypt(ciphertext=ciphertext)

    def decrypt(self, ciphertext: Union[int, Tuple[int, int]]) -> int:
        """
        Decrypt a given ciphertext with Ishai-Paskin
        Args:
            ciphertext (int or tuple): ciphertext created by encrypt, or
                (level, ciphertext) output of a decision tree evaluation
        Returns:
            plaintext (int): restored message
        """
        if isinstance(ciphertext, int):
            return super().decrypt(ciphertext)

        level, value = ciphertext
        # peel encryption layers from outer to inner
        for current_level in range(level, 0, -1):
            value = self.decrypt_at_level(ciphertext=value, level=current_level)
        return value
