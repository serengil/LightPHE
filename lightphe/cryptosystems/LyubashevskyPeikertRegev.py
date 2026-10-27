# built-in dependencies
import math
import hashlib
import secrets
from typing import Optional, List

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/LyubashevskyPeikertRegev.py")

# floats are scaled by powers of 10, which exceeds the small plaintext space,
# and multiplies the noise in ciphertexts by the same factor
FLOAT_NOT_SUPPORTED_MSG = (
    "Lyubashevsky-Peikert-Regev does not support float values or tensors, because they are"
    " scaled by powers of 10, which exceed its small plaintext space and noise budget."
    " Use integers instead."
)

# ciphertext modulus q = 2^LOG_Q
LOG_Q = 50

# default plaintext modulus t = 2^DEFAULT_LOG_T
DEFAULT_LOG_T = 24

# secret and errors are sampled from centered binomial distribution with this parameter
# its standard deviation is sqrt(ETA / 2) = 3.24, and its values are in [-ETA, ETA]
ETA = 21

# fresh noise must stay below this many standard deviations for correct decryption
NOISE_TAIL = 12


class LyubashevskyPeikertRegev(Homomorphic):
    """
    Lyubashevsky-Peikert-Regev algorithm is homomorphic with respect to the addition.
    Also, it supports multiplying a ciphertext with a plain constant. It is Regev's
    cryptosystem over a polynomial ring, and it is quantum resistant. Its security relies
    on the ring learning with errors (Ring-LWE) problem like Brakerski-Vaikuntanathan.

    It works in the polynomial ring R_q = Z_q[x] / (x^d + 1).
        - private key: polynomial s with small coefficients
        - public key: a and b = a s + e, where e is a small error polynomial
        - encryption: c1 = a u + e1, and c2 = constant term of (b u) + e2 + m * q / t
        - decryption: c2 - constant term of (c1 s) = m * q / t + noise, so m is restored
            by rounding
    a is expanded from a public seed with SHAKE-128, so the public key is the seed and b.

    Regev uses a random n x n matrix A, whereas this uses the negacyclic matrix of a single
    polynomial a, so the public structure is n times smaller, and c1 = a u is a single
    polynomial multiplication instead of a matrix-vector product. Message is encoded into
    the constant term only, which is the only coefficient decryption reads, so other
    coefficients of c2 are dropped. Thus, a ciphertext has d + 1 coefficients like Regev,
    instead of 2d of the original scheme. Dropping parts of a ciphertext does not help
    an attacker, so the security is the same.

    key_size is the ring degree d, a power of 2. Default is 2048. With q = 2^50, degree
    2048 gives about 128-bit security against quantum attacks according to the tables
    of Homomorphic Encryption Standard (log q must be at most 51 for d = 2048).
    Smaller degrees are not secure, and are for testing only.

    Notice that its plaintext space is small, 2^24 by default, and every ciphertext has
    noise. Noise grows with homomorphic operations: addition adds the noise of ciphertexts,
    and multiplying with a constant k multiplies the noise by |k|. Decryption returns a
    wrong result without any error when the noise exceeds q / 2t. Fresh noise is about
    2^13 for d = 2048, and the limit is 2^25 by default, so there is room for thousands of
    additions or multiplication with constants up to a few thousands. A greater plaintext
    space can be set with plaintext_limit in exchange of a smaller room for noise.
    Floats and tensors are not supported, as they are scaled by powers of 10.
    Ciphertexts have d + 1 entries of 50 bits each, about 12.8 KB for d = 2048.

    Ref: Lyubashevsky, V., Peikert, C., Regev, O. (2010). On Ideal Lattices and Learning
        with Errors over Rings. EUROCRYPT 2010.
    Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
        HomomorphicEncryption.org.
    """

    REQUIRED_KEYS = {
        "public_key": ["d", "q", "t", "seed", "b"],
        "private_key": ["s"],
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
            key_size (int): ring degree, a power of 2. Default is 2048.
            plaintext_limit (int): upper bound for plaintext values. It is rounded up to
                a power of 2. Default is 2^24. Greater values leave less room for noise.
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 2048, plaintext_limit=plaintext_limit
        )
        self.plaintext_modulo = self.keys["public_key"]["t"]
        self.ciphertext_modulo = self.keys["public_key"]["q"]
        # a expanded from the seed when needed
        self.__a: Optional[List[int]] = None

    def generate_keys(self, key_size: int, plaintext_limit: Optional[int] = None) -> dict:
        """
        Generate public and private keys of Lyubashevsky-Peikert-Regev cryptosystem
        Args:
            key_size (int): ring degree
            plaintext_limit (int): upper bound for plaintext values
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        d = key_size
        if d < 8 or d & (d - 1) != 0:
            raise ValueError(
                f"Key size {d} must be a power of 2 and at least 8 for"
                " Lyubashevsky-Peikert-Regev"
            )

        q = 1 << LOG_Q
        t = 1 << DEFAULT_LOG_T
        if plaintext_limit is not None:
            if plaintext_limit < 2:
                raise ValueError("Plaintext limit must be at least 2")
            t = 1 << (plaintext_limit - 1).bit_length()

        # fresh ciphertexts must be decrypted correctly
        noise_bound = self.__noise_bound(d)
        if q // t // 2 <= noise_bound:
            raise ValueError(
                f"Plaintext limit {plaintext_limit} is too large for Lyubashevsky-Peikert-Regev."
                f" It must be less than {q // (2 * noise_bound)} for degree {d}."
            )
        logger.debug(
            f"noise of fresh ciphertexts can grow {(q // t // 2) / noise_bound:.0f} times"
        )

        seed = secrets.randbits(256)
        a = self.__expand(seed=seed, d=d)
        s = self.__sample_small(d)
        e = self.__sample_small(d)

        # b = a s + e
        a_s = self.__poly_mul(a, [x % q for x in s], d)
        b = [(x + y) % q for x, y in zip(a_s, e)]

        keys["public_key"]["d"] = d
        keys["public_key"]["q"] = q
        keys["public_key"]["t"] = t
        keys["public_key"]["seed"] = seed
        keys["public_key"]["b"] = b

        keys["private_key"]["s"] = s

        return keys

    def generate_random_key(self) -> List[int]:
        """
        Lyubashevsky-Peikert-Regev requires a one-time small random polynomial per encryption
        Returns:
            random key (list): coefficients of small random polynomial u
        """
        return self.__sample_small(self.keys["public_key"]["d"])

    def encrypt(self, plaintext: int, random_key: Optional[List[int]] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Lyubashevsky-Peikert-Regev
        Args:
            plaintext (int): message to encrypt in [0, t)
            random_key (list): coefficients of small random polynomial u
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): d coefficients of c1 = a u + e1, and
                c2 = constant term of (b u) + e2 + m q / t
        """
        d = self.keys["public_key"]["d"]
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]
        b = self.keys["public_key"]["b"]
        u = random_key or self.generate_random_key()

        if plaintext >= t:
            plaintext = plaintext % t
            logger.debug(
                f"Lyubashevsky-Peikert-Regev can encrypt messages [0, {t}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        if self.__a is None:
            self.__a = self.__expand(seed=self.keys["public_key"]["seed"], d=d)

        e1 = self.__sample_small(d)
        e2 = self.__sample_small(1)[0]

        c1 = [(x + y) % q for x, y in zip(self.__poly_mul(self.__a, [x % q for x in u], d), e1)]
        c2 = (self.__constant_term(b, u) + e2 + plaintext * (q // t)) % q
        return tuple(c1) + (c2,)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Lyubashevsky-Peikert-Regev
        Args:
            ciphertext (tuple): encrypted message
        Returns:
            plaintext (int): restored message
        """
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]
        s = self.keys["private_key"]["s"]
        delta = q // t

        *c1, c2 = ciphertext
        # m * q / t + noise
        noisy_message = (c2 - self.__constant_term(c1, s)) % q
        return ((noisy_message + delta // 2) // delta) % t

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Noise of the result is the sum of noises of the ciphertexts.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Lyubashevsky-Peikert-Regev
            ciphertext2 (tuple): 2nd ciphertext created with Lyubashevsky-Peikert-Regev
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Lyubashevsky-Peikert-Regev
        """
        q = self.keys["public_key"]["q"]
        return tuple((x + y) % q for x, y in zip(ciphertext1, ciphertext2))

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Noise of the result is the noise of the ciphertext times |constant|.
        Args:
            ciphertext (tuple): ciphertext created with Lyubashevsky-Peikert-Regev
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Lyubashevsky-Peikert-Regev
        """
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]

        # centered representative keeps the noise small for negative constants,
        # e.g. t - 1 is multiplied as -1. as t divides q, this does not change the result.
        constant = constant % t
        if constant > t // 2:
            constant -= t

        return tuple((x * constant) % q for x in ciphertext)

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
    def __poly_mul(poly1: List[int], poly2: List[int], d: int) -> List[int]:
        """
        Multiply two polynomials in Z_q[x] / (x^d + 1) with Kronecker substitution.
            Coefficients are packed into big integers, so that a single big integer
            multiplication computes all coefficients of the product, which is much faster
            than multiplying coefficients one by one in Python.
        Args:
            poly1 (list): d coefficients in [0, q)
            poly2 (list): d coefficients in [0, q)
            d (int): ring degree
        Returns:
            product (list): d coefficients in [0, q)
        """
        # each coefficient of the product is a sum of d products less than q^2
        width = math.ceil((2 * LOG_Q + d.bit_length()) / 8)
        packed1 = int.from_bytes(b"".join(x.to_bytes(width, "little") for x in poly1), "little")
        packed2 = int.from_bytes(b"".join(x.to_bytes(width, "little") for x in poly2), "little")
        product = (packed1 * packed2).to_bytes(2 * d * width, "little")
        coefficients = [
            int.from_bytes(product[i * width : (i + 1) * width], "little") for i in range(2 * d)
        ]
        # x^d = -1
        q = 1 << LOG_Q
        return [(coefficients[i] - coefficients[i + d]) % q for i in range(d)]

    @staticmethod
    def __constant_term(poly1: List[int], poly2: List[int]) -> int:
        """
        Constant term of the product of two polynomials in Z[x] / (x^d + 1),
            i.e. p1_0 p2_0 - sum of p1_i p2_(d-i) for i in [1, d)
        """
        d = len(poly1)
        return poly1[0] * poly2[0] - sum(poly1[i] * poly2[d - i] for i in range(1, d))

    @staticmethod
    def __sample_small(size: int) -> List[int]:
        """
        Sample from centered binomial distribution with cryptographically secure randomness
        Args:
            size (int): number of samples
        Returns:
            samples (list): integers in [-ETA, ETA]
        """
        mask = (1 << ETA) - 1
        samples = []
        for _ in range(size):
            bits = secrets.randbits(2 * ETA)
            samples.append(bin(bits & mask).count("1") - bin(bits >> ETA).count("1"))
        return samples

    @staticmethod
    def __expand(seed: int, d: int) -> List[int]:
        """
        Expand the public polynomial a from its seed with SHAKE-128. q is a power of 2,
            so each coefficient is uniform in [0, q) when its bits are masked.
        """
        width = math.ceil(LOG_Q / 8)
        mask = (1 << LOG_Q) - 1
        stream = hashlib.shake_128(seed.to_bytes(32, "big")).digest(d * width)
        return [
            int.from_bytes(stream[i * width : (i + 1) * width], "little") & mask
            for i in range(d)
        ]

    @staticmethod
    def __noise_bound(d: int) -> int:
        """
        Bound of the noise constant term of (e u) + e2 - constant term of (e1 s) in fresh
            ciphertexts. It sums 2d products of small coefficients like Regev.
        Args:
            d (int): ring degree
        Returns:
            bound (int)
        """
        variance = ETA / 2
        return math.ceil(NOISE_TAIL * variance * math.sqrt(2 * d)) + ETA
