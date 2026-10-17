# built-in dependencies
import math
import secrets
from operator import mul
from typing import Optional, List

# 3rd party dependencies
import sympy

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/GentryHaleviVaikuntanathan.py")

# floats are scaled by powers of 10, which exceeds the small plaintext space
FLOAT_NOT_SUPPORTED_MSG = (
    "Gentry-Halevi-Vaikuntanathan does not support float values or tensors, because they are"
    " scaled by powers of 10, which exceed its small plaintext space. Use integers instead."
)

# shown whenever the cryptosystem is built
INSECURE_WARNING_MSG = (
    "Gentry-Halevi-Vaikuntanathan is for learning purposes only. Its ciphertexts are huge"
    " matrices for secure parameters, so it supports tiny key sizes that are not secure."
    " Use Brakerski-Vaikuntanathan for a practical alternative."
)

# lattice dimension is limited, as ciphertexts are m x m matrices where m grows with n log q
MIN_KEY_SIZE = 2
MAX_KEY_SIZE = 8
DEFAULT_KEY_SIZE = 4

# default plaintext modulus p
DEFAULT_PLAINTEXT_MODULO = 101

# room for noise growth after a multiplication in bits, i.e. for additions and constants
NOISE_MARGIN_BITS = 12

# errors are sampled from centered binomial distribution with this parameter
ETA = 2

FRESH = 1
MULTIPLIED = 2


class GentryHaleviVaikuntanathan(Homomorphic):
    """
    Gentry-Halevi-Vaikuntanathan algorithm is homomorphic with respect to the addition, and
    supports one multiplication of ciphertexts like Boneh-Goh-Nissim, without pairings.
    Its security relies on learning with errors (LWE) problem.

    THIS IS FOR LEARNING PURPOSES ONLY, AND IT IS NOT SECURE. Ciphertexts are m x m matrices
    where m grows with n log q, so secure parameters would need ciphertexts of terabytes.
    Here, the lattice dimension n is between 2 and 8, which offers no security at all.
    Use Brakerski-Vaikuntanathan for a practical and quantum resistant alternative.

    Matrices are over Z_q where q is a power of 2, and plaintexts are in Z_p for an odd prime p.
        - private key: short m x m matrix T, which is full rank and satisfies T A = 0 mod q.
            It is generated with the gadget trapdoor of Micciancio-Peikert:
            A^T = [A_bar | G - A_bar R] where G is the gadget matrix of powers of 2.
        - public key: m x n matrix A
        - encryption of m: C = A S + p X + m I mod q for uniformly random S and small X
        - decryption: T C T^T mod q = T (p X + m I) T^T, as T A = 0. When its entries are
            small enough, it equals T (p X + m I) T^T over integers, so reducing it modulo p
            and multiplying with T^-1 and T^-T modulo p restores m I.
        - multiplication: C1 C2^T, which is decrypted in the same way to m1 m2 I, as
            T (A S1 + Z1)(A S2 + Z2)^T T^T = T Z1 Z2^T T^T
    The original scheme encrypts m x m matrices of plaintexts. Here, a single plaintext
    is encrypted as the scalar matrix m I.

    Noise grows with homomorphic operations, and decryption returns a wrong result without
    any error when it exceeds q / 2. q is chosen to leave room for multiplying a product
    with constants up to a few thousands, or for adding thousands of products.

    Ref: Gentry, C., Halevi, S., Vaikuntanathan, V. (2010). A Simple BGN-Type Cryptosystem
        from LWE. EUROCRYPT 2010.
    Ref: Micciancio, D., Peikert, C. (2012). Trapdoors for Lattices: Simpler, Tighter,
        Faster, Smaller. EUROCRYPT 2012.
    """

    REQUIRED_KEYS = {
        "public_key": ["A", "q", "p"],
        "private_key": ["T"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        plaintext_limit: Optional[int] = None,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): lattice dimension n in [2, 8]. Default is 4.
            plaintext_limit (int): upper bound for plaintext values. Plaintext modulus p is
                the smallest prime greater than or equal to it. Default is 101.
        """
        logger.warn(INSECURE_WARNING_MSG)
        self.keys = keys or self.generate_keys(
            key_size=key_size or DEFAULT_KEY_SIZE, plaintext_limit=plaintext_limit
        )
        self.plaintext_modulo = self.keys["public_key"]["p"]
        self.ciphertext_modulo = self.keys["public_key"]["q"]

    def generate_keys(self, key_size: int, plaintext_limit: Optional[int] = None) -> dict:
        """
        Generate public and private keys of Gentry-Halevi-Vaikuntanathan cryptosystem
        Args:
            key_size (int): lattice dimension n
            plaintext_limit (int): upper bound for plaintext values
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        n = key_size
        if not MIN_KEY_SIZE <= n <= MAX_KEY_SIZE:
            raise ValueError(
                f"Key size {n} is not supported. Gentry-Halevi-Vaikuntanathan is for learning"
                f" purposes only, and its key size must be in [{MIN_KEY_SIZE}, {MAX_KEY_SIZE}]."
            )

        # T must be invertible modulo p, and det(T) is a power of 2
        p = DEFAULT_PLAINTEXT_MODULO
        if plaintext_limit is not None:
            p = sympy.nextprime(max(plaintext_limit, 3) - 1)

        m_bar = 2 * n
        k = self.__modulus_bits(n=n, m_bar=m_bar, p=p)
        q = 1 << k
        nk = n * k
        logger.debug(f"n = {n}, log q = {k}, m = {m_bar + nk}, p = {p}")

        # A^T = [A_bar | G - A_bar R], where G = I_n (x) (1, 2, ..., 2^(k-1))
        a_bar = [[secrets.randbelow(q) for _ in range(m_bar)] for _ in range(n)]
        r = [[secrets.randbelow(3) - 1 for _ in range(nk)] for _ in range(m_bar)]
        a_bar_r = self.__matmul(a_bar, r)
        a_transposed = [
            a_bar[i]
            + [(((1 << (c % k)) if c // k == i else 0) - a_bar_r[i][c]) % q for c in range(nk)]
            for i in range(n)
        ]

        # W is the bit decomposition of -A_bar, so that G W = -A_bar mod q
        w = [[0] * m_bar for _ in range(nk)]
        for j in range(m_bar):
            for i in range(n):
                value = (-a_bar[i][j]) % q
                for bit in range(k):
                    w[i * k + bit][j] = (value >> bit) & 1

        # S_G = I_n (x) S_k, whose columns 2 e_i - e_(i+1) and 2 e_k are orthogonal to the gadget
        s_g = [[0] * nk for _ in range(nk)]
        for block in range(n):
            for i in range(k):
                s_g[block * k + i][block * k + i] = 2
                if i + 1 < k:
                    s_g[block * k + i + 1][block * k + i] = -1

        # S = [[I + R W, R S_G], [W, S_G]] is a short basis with A^T S = 0 mod q
        r_w = self.__matmul(r, w)
        r_s_g = self.__matmul(r, s_g)
        s = [
            [(1 if i == j else 0) + r_w[i][j] for j in range(m_bar)] + r_s_g[i]
            for i in range(m_bar)
        ]
        s += [w[i] + s_g[i] for i in range(nk)]

        t = [list(column) for column in zip(*s)]
        a = [list(column) for column in zip(*a_transposed)]

        keys["public_key"]["A"] = a
        keys["public_key"]["q"] = q
        keys["public_key"]["p"] = p

        keys["private_key"]["T"] = t
        # first row of T^-1 mod p is enough to restore scalar matrices m I
        keys["private_key"]["u"] = self.__first_row_of_inverse(t, p)

        return keys

    def generate_random_key(self) -> List[List[int]]:
        """
        Gentry-Halevi-Vaikuntanathan requires a uniformly random n x m matrix S per encryption
        Returns:
            random key (list): matrix S
        """
        a = self.keys["public_key"]["A"]
        q = self.keys["public_key"]["q"]
        return [[secrets.randbelow(q) for _ in range(len(a))] for _ in range(len(a[0]))]

    def encrypt(self, plaintext: int, random_key: Optional[List[List[int]]] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Gentry-Halevi-Vaikuntanathan
        Args:
            plaintext (int): message to encrypt in [0, p)
            random_key (list): uniformly random n x m matrix S
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): level and m x m matrix C = A S + p X + m I mod q
        """
        a = self.keys["public_key"]["A"]
        q = self.keys["public_key"]["q"]
        p = self.keys["public_key"]["p"]
        s = random_key or self.generate_random_key()
        m = len(a)

        if plaintext >= p:
            plaintext = plaintext % p
            logger.debug(
                f"Gentry-Halevi-Vaikuntanathan can encrypt messages [0, {p}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        a_s = self.__matmul(a, s)
        matrix = tuple(
            tuple(
                (a_s[i][j] + p * self.__sample_small() + (plaintext if i == j else 0)) % q
                for j in range(m)
            )
            for i in range(m)
        )
        return FRESH, matrix

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Gentry-Halevi-Vaikuntanathan
        Args:
            ciphertext (tuple): level and matrix
        Returns:
            plaintext (int): restored message
        """
        q = self.keys["public_key"]["q"]
        p = self.keys["public_key"]["p"]
        t = self.keys["private_key"]["T"]
        if "u" not in self.keys["private_key"]:
            self.keys["private_key"]["u"] = self.__first_row_of_inverse(t, p)
        u = self.keys["private_key"]["u"]

        _, matrix = ciphertext

        # E = T C T^T mod q, centered, equals T (p X + B) T^T over integers
        t_c = self.__matmul(t, matrix)
        e = [
            [x - q if x > q // 2 else x for x in (value % q for value in row)]
            for row in self.__matmul_transposed(t_c, t)
        ]

        # B = T^-1 E T^-T mod p, and its first diagonal entry is the message
        u_e = [sum(map(mul, u, column)) for column in zip(*e)]
        return sum(map(mul, u_e, u)) % p

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Fresh and multiplied ciphertexts can be added, as they are decrypted in the same way.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Gentry-Halevi-Vaikuntanathan
            ciphertext2 (tuple): 2nd ciphertext created with Gentry-Halevi-Vaikuntanathan
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Gentry-Halevi-Vaikuntanathan
        """
        q = self.keys["public_key"]["q"]
        level1, matrix1 = ciphertext1
        level2, matrix2 = ciphertext2
        matrix = tuple(
            tuple((x + y) % q for x, y in zip(row1, row2)) for row1, row2 in zip(matrix1, matrix2)
        )
        return max(level1, level2), matrix

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic multiplication on encrypted data.
        Result of this must be equal to E(m1 * m2). It is the matrix product C1 C2^T.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Gentry-Halevi-Vaikuntanathan
            ciphertext2 (tuple): 2nd ciphertext created with Gentry-Halevi-Vaikuntanathan
        Returns:
            ciphertext3 (tuple): multiplied ciphertext
        """
        q = self.keys["public_key"]["q"]
        level1, matrix1 = ciphertext1
        level2, matrix2 = ciphertext2
        if level1 != FRESH or level2 != FRESH:
            raise ValueError(
                "Gentry-Halevi-Vaikuntanathan supports only one multiplication. "
                "Multiplied ciphertexts cannot be multiplied with ciphertexts again."
            )
        product = self.__matmul_transposed(matrix1, matrix2)
        return MULTIPLIED, tuple(tuple(x % q for x in row) for row in product)

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Noise of the result is the noise of the ciphertext times |constant|.
        Args:
            ciphertext (tuple): ciphertext created with Gentry-Halevi-Vaikuntanathan
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Gentry-Halevi-Vaikuntanathan
        """
        q = self.keys["public_key"]["q"]
        p = self.keys["public_key"]["p"]

        # centered representative keeps the noise small for negative constants
        constant = constant % p
        if constant > p // 2:
            constant -= p

        level, matrix = ciphertext
        return level, tuple(tuple((x * constant) % q for x in row) for row in matrix)

    def reencrypt(self, ciphertext: tuple) -> tuple:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (tuple): given ciphertext
        Returns:
            new ciphertext (tuple): different ciphertext for same plaintext
        """
        neutral_element = 0
        neutral_encrypted = self.encrypt(plaintext=neutral_element)
        return self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    @staticmethod
    def __modulus_bits(n: int, m_bar: int, p: int) -> int:
        """
        Bits of q, so that the noise of a product stays below q / 2 with a margin.
            Noise of a product is about p^2 m^2 times a small factor, and m = m_bar + n log q,
            so it is found iteratively.
        """
        k = 32
        while True:
            m = m_bar + n * k
            required = math.ceil(2 * math.log2(p) + 2 * math.log2(m) + 2 + NOISE_MARGIN_BITS)
            if required <= k:
                return k
            k = required

    @staticmethod
    def __sample_small() -> int:
        """
        Sample from centered binomial distribution with cryptographically secure randomness
        """
        bits = secrets.randbits(2 * ETA)
        return bin(bits & ((1 << ETA) - 1)).count("1") - bin(bits >> ETA).count("1")

    @staticmethod
    def __matmul(left: list, right: list) -> List[List[int]]:
        """
        Matrix product left x right
        """
        columns = list(zip(*right))
        return [[sum(map(mul, row, column)) for column in columns] for row in left]

    @staticmethod
    def __matmul_transposed(left: list, right: list) -> List[List[int]]:
        """
        Matrix product left x right^T
        """
        return [[sum(map(mul, row, other)) for other in right] for row in left]

    @staticmethod
    def __first_row_of_inverse(matrix: List[List[int]], p: int) -> List[int]:
        """
        First row of the inverse of a matrix modulo prime p with Gauss-Jordan elimination
        """
        size = len(matrix)
        augmented = [
            [x % p for x in row] + [1 if i == j else 0 for j in range(size)]
            for i, row in enumerate(matrix)
        ]
        for column in range(size):
            pivot = next(row for row in range(column, size) if augmented[row][column])
            augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
            inverse = pow(augmented[column][column], -1, p)
            augmented[column] = [(x * inverse) % p for x in augmented[column]]
            for row in range(size):
                factor = augmented[row][column]
                if row != column and factor:
                    augmented[row] = [
                        (x - factor * y) % p for x, y in zip(augmented[row], augmented[column])
                    ]
        return augmented[0][size:]
