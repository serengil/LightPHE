# built-in dependencies
import math
import hashlib
import secrets
from typing import Optional, List

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/Regev.py")

# floats are scaled by powers of 10, which exceeds the small plaintext space of Regev,
# and multiplies the noise in ciphertexts by the same factor
FLOAT_NOT_SUPPORTED_MSG = (
    "Regev does not support float values or tensors, because they are scaled by powers"
    " of 10, which exceed its small plaintext space and noise budget. Use integers instead."
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


class Regev(Homomorphic):
    """
    Regev algorithm is homomorphic with respect to the addition.
    Also, it supports multiplying a ciphertext with a plain constant.
    It is the first quantum resistant algorithm in LightPHE. Its security relies on the
    learning with errors (LWE) problem, which is believed to be hard for quantum computers,
    unlike factoring and discrete logarithm problems that other algorithms rely on.

    This is the Lindner-Peikert form of Regev's cryptosystem, which is the one used in
    practice, e.g. by FrodoKEM. Original form requires a public key matrix with about
    n log q rows, whereas this needs an n x n matrix A.
        - private key: secret vector s with small entries
        - public key: A and b = A s + e mod q, where e is a small error vector
        - encryption: c1 = A^T r + e1 and c2 = <b, r> + e2 + m * q / t mod q
        - decryption: c2 - <c1, s> = m * q / t + noise, so m is restored by rounding
    A is expanded from a public seed with SHAKE-128, so the public key is the seed and b.

    key_size is the lattice dimension n. Default is 2048. With q = 2^50, dimension 2048
    or more gives about 128-bit security against quantum attacks according to the tables
    of Homomorphic Encryption Standard (log q must be at most 51 for n = 2048).
    Smaller dimensions are not secure, and are for testing only.

    Notice that its plaintext space is small, 2^24 by default, and every ciphertext has
    noise. Noise grows with homomorphic operations: addition adds the noise of ciphertexts,
    and multiplying with a constant k multiplies the noise by |k|. Decryption returns a
    wrong result without any error when the noise exceeds q / 2t. Fresh noise is about
    2^13 for n = 2048, and the limit is 2^25 by default, so there is room for thousands of
    additions or multiplication with constants up to a few thousands. A greater plaintext
    space can be set with plaintext_limit in exchange of a smaller room for noise.
    Floats and tensors are not supported, as they are scaled by powers of 10.
    Ciphertexts have n + 1 entries of 50 bits each, about 12.8 KB for n = 2048.

    Ref: Regev, O. (2005). On Lattices, Learning with Errors, Random Linear Codes,
        and Cryptography. STOC 2005.
    Ref: Lindner, R., Peikert, C. (2011). Better Key Sizes (and Attacks) for LWE-Based
        Encryption. CT-RSA 2011.
    Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
        HomomorphicEncryption.org.
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "q", "t", "seed", "b"],
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
            key_size (int): lattice dimension. Default is 2048.
            plaintext_limit (int): upper bound for plaintext values. It is rounded up to
                a power of 2. Default is 2^24. Greater values leave less room for noise.
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 2048, plaintext_limit=plaintext_limit
        )
        self.plaintext_modulo = self.keys["public_key"]["t"]
        self.ciphertext_modulo = self.keys["public_key"]["q"]
        # rows of A packed into integers, expanded from the seed when needed
        self.__packed_rows: Optional[List[int]] = None

    def generate_keys(self, key_size: int, plaintext_limit: Optional[int] = None) -> dict:
        """
        Generate public and private keys of Regev cryptosystem
        Args:
            key_size (int): lattice dimension
            plaintext_limit (int): upper bound for plaintext values
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        n = key_size
        if n < 8:
            raise ValueError(f"Key size {n} is too small for Regev")

        q = 1 << LOG_Q
        t = 1 << DEFAULT_LOG_T
        if plaintext_limit is not None:
            if plaintext_limit < 2:
                raise ValueError("Plaintext limit must be at least 2")
            t = 1 << (plaintext_limit - 1).bit_length()

        # fresh ciphertexts must be decrypted correctly
        noise_bound = self.__noise_bound(n)
        if q // t // 2 <= noise_bound:
            raise ValueError(
                f"Plaintext limit {plaintext_limit} is too large for Regev. "
                f"It must be less than {q // (2 * noise_bound)} for dimension {n}."
            )
        logger.debug(
            f"noise of fresh ciphertexts can grow {(q // t // 2) / noise_bound:.0f} times"
        )

        seed = secrets.randbits(256)
        s = self.__sample_small(n)
        e = self.__sample_small(n)

        # b = A s + e mod q, where columns of A are packed into integers
        columns = self.__expand(seed=seed, n=n, columns=True)
        b = [(x + y) % q for x, y in zip(self.__packed_sum(columns, s, n), e)]

        keys["public_key"]["n"] = n
        keys["public_key"]["q"] = q
        keys["public_key"]["t"] = t
        keys["public_key"]["seed"] = seed
        keys["public_key"]["b"] = b

        keys["private_key"]["s"] = s

        return keys

    def generate_random_key(self) -> List[int]:
        """
        Regev requires to generate a one-time small random vector per encryption
        Returns:
            random key (list): small random vector r
        """
        return self.__sample_small(self.keys["public_key"]["n"])

    def encrypt(self, plaintext: int, random_key: Optional[List[int]] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Regev
        Args:
            plaintext (int): message to encrypt in [0, t)
            random_key (list): small random vector r
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): n entries of c1 = A^T r + e1, and c2 = <b, r> + e2 + m q / t
        """
        n = self.keys["public_key"]["n"]
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]
        b = self.keys["public_key"]["b"]
        r = random_key or self.generate_random_key()

        if plaintext >= t:
            plaintext = plaintext % t
            logger.debug(
                f"Regev can encrypt messages [0, {t}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        if self.__packed_rows is None:
            self.__packed_rows = self.__expand(
                seed=self.keys["public_key"]["seed"], n=n, columns=False
            )

        e1 = self.__sample_small(n)
        e2 = self.__sample_small(1)[0]

        c1 = [(x + y) % q for x, y in zip(self.__packed_sum(self.__packed_rows, r, n), e1)]
        c2 = (sum(x * y for x, y in zip(b, r)) + e2 + plaintext * (q // t)) % q
        return tuple(c1) + (c2,)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Regev
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
        noisy_message = (c2 - sum(x * y for x, y in zip(c1, s))) % q
        return ((noisy_message + delta // 2) // delta) % t

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Noise of the result is the sum of noises of the ciphertexts.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Regev
            ciphertext2 (tuple): 2nd ciphertext created with Regev
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Regev
        """
        q = self.keys["public_key"]["q"]
        return tuple((x + y) % q for x, y in zip(ciphertext1, ciphertext2))

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Noise of the result is the noise of the ciphertext times |constant|.
        Args:
            ciphertext (tuple): ciphertext created with Regev
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Regev
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
    def __noise_bound(n: int) -> int:
        """
        Bound of the noise <e, r> + e2 - <s, e1> in fresh ciphertexts
        Args:
            n (int): lattice dimension
        Returns:
            bound (int)
        """
        variance = ETA / 2
        return math.ceil(NOISE_TAIL * variance * math.sqrt(2 * n)) + ETA

    @staticmethod
    def __slot_bytes(n: int) -> int:
        """
        Size of a slot in packed integers, which must hold a sum of n products of an
            entry of A and a small number without overflow
        """
        return math.ceil((LOG_Q + (ETA * n).bit_length()) / 8)

    @staticmethod
    def __expand(seed: int, n: int, columns: bool) -> List[int]:
        """
        Expand the public matrix A from its seed with SHAKE-128, and pack its rows or
            columns into integers. Packing lets Python add n entries in a single
            big integer addition, which is much faster than a loop.
        Args:
            seed (int): public seed
            n (int): lattice dimension
            columns (bool): pack columns if True, rows otherwise
        Returns:
            packed (list): n integers, each having n slots of entries in [0, q)
        """
        width = Regev.__slot_bytes(n)
        stream = hashlib.shake_128(seed.to_bytes(32, "big")).digest(n * n * width)
        mask = int.from_bytes(((1 << LOG_Q) - 1).to_bytes(width, "little") * n, "little")

        packed = []
        for i in range(n):
            if columns:
                # entry (j, i) of A for all j is in every n * width bytes
                chunk = bytearray(n * width)
                for k in range(width):
                    chunk[k::width] = stream[i * width + k :: n * width]
            else:
                chunk = stream[i * n * width : (i + 1) * n * width]
            packed.append(int.from_bytes(chunk, "little") & mask)
        return packed

    @staticmethod
    def __packed_sum(packed: List[int], weights: List[int], n: int) -> List[int]:
        """
        Weighted sum of packed vectors with small weights
        Args:
            packed (list): n packed vectors
            weights (list): n small integers
            n (int): lattice dimension
        Returns:
            sum (list): n integers, not reduced modulo q
        """
        width = Regev.__slot_bytes(n)
        # slots must stay non-negative, so negative weights are summed separately
        positive, negative = 0, 0
        for vector, weight in zip(packed, weights):
            if weight > 0:
                positive += vector * weight
            elif weight < 0:
                negative += vector * -weight

        positive_bytes = positive.to_bytes(n * width, "little")
        negative_bytes = negative.to_bytes(n * width, "little")
        return [
            int.from_bytes(positive_bytes[j * width : (j + 1) * width], "little")
            - int.from_bytes(negative_bytes[j * width : (j + 1) * width], "little")
            for j in range(n)
        ]
