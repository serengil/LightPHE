# built-in dependencies
import math
import hashlib
import secrets
from typing import Optional, List

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/BrakerskiVaikuntanathan.py")

# floats are scaled by powers of 10, which exceeds the small plaintext space,
# and multiplies the noise in ciphertexts by the same factor
FLOAT_NOT_SUPPORTED_MSG = (
    "Brakerski-Vaikuntanathan does not support float values or tensors, because they are"
    " scaled by powers of 10, which exceed its small plaintext space and noise budget."
    " Use integers instead."
)

# ciphertext modulus q is the greatest prime less than 2^LOG_Q.
# it must be co-prime to t, otherwise public key reveals the secret modulo t.
LOG_Q = 100
Q = 1267650600228229401496703205361

# default plaintext modulus t = 2^DEFAULT_LOG_T
DEFAULT_LOG_T = 24

# secret and errors are sampled from centered binomial distribution with this parameter
# its standard deviation is sqrt(ETA / 2) = 3.24, and its values are in [-ETA, ETA]
ETA = 21

# noise must stay below this many standard deviations for correct decryption
NOISE_TAIL = 12

# a ciphertext is a pair of polynomials, and a multiplied ciphertext is a triple
FRESH_SIZE = 2
MULTIPLIED_SIZE = 3


class BrakerskiVaikuntanathan(Homomorphic):
    """
    Brakerski-Vaikuntanathan algorithm is homomorphic with respect to the addition, and
    supports one multiplication of ciphertexts like Boneh-Goh-Nissim. Unlike Boneh-Goh-Nissim,
    it does not need pairings, and it is quantum resistant. Its security relies on the
    ring learning with errors (Ring-LWE) problem, which is believed to be hard for quantum
    computers.

    It works in the polynomial ring R_q = Z_q[x] / (x^d + 1).
        - private key: polynomial s with small coefficients
        - public key: a and b = -(a s + t e), where e is a small error polynomial
        - encryption: c0 = b u + t g + m, c1 = a u + t f where u, f, g are small
        - decryption: c0 + c1 s = m + t (g + f s - e u) mod q, so m is its constant term mod t
        - multiplication: (c0, c1) x (c0', c1') = (c0 c0', c0 c1' + c1 c0', c1 c1'),
            which is decrypted with (1, s, s^2) as (c0 + c1 s)(c0' + c1' s) = m m' + t (...)
    Multiplied ciphertexts are triples of polynomials. They can be added with each other
    and with fresh ciphertexts, and multiplied with constants, but cannot be multiplied
    with ciphertexts again. a is expanded from a public seed with SHAKE-128.

    key_size is the ring degree d, a power of 2. Default is 4096. With q around 2^100,
    degree 4096 gives about 128-bit security against quantum attacks according to the tables
    of Homomorphic Encryption Standard (log q must be at most 101 for d = 4096).
    Smaller degrees are not secure, and are for testing only.

    Notice that its plaintext space is small, 2^24 by default, and every ciphertext has
    noise growing with homomorphic operations: addition adds the noises, multiplying with
    a constant k multiplies the noise by |k|, and multiplication of ciphertexts multiplies
    their noises. Decryption returns a wrong result without any error when the noise exceeds
    q / 2. With default settings, a multiplied ciphertext still has room for millions of
    times more noise, i.e. for many additions and multiplications with constants.
    A greater plaintext space can be set with plaintext_limit in exchange of a smaller room.
    Floats and tensors are not supported, as they are scaled by powers of 10.
    Ciphertexts have 2 polynomials of d coefficients of 100 bits, about 100 KB for d = 4096.

    Ref: Brakerski, Z., Vaikuntanathan, V. (2011). Fully Homomorphic Encryption from Ring-LWE
        and Security for Key Dependent Messages. CRYPTO 2011.
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
            key_size (int): ring degree, a power of 2. Default is 4096.
            plaintext_limit (int): upper bound for plaintext values. It is rounded up to
                a power of 2. Default is 2^24. Greater values leave less room for noise.
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 4096, plaintext_limit=plaintext_limit
        )
        self.plaintext_modulo = self.keys["public_key"]["t"]
        self.ciphertext_modulo = self.keys["public_key"]["q"]
        # a expanded from the seed, and s^2 for decryption of multiplied ciphertexts
        self.__a: Optional[List[int]] = None
        self.__s_square: Optional[List[int]] = None

    def generate_keys(self, key_size: int, plaintext_limit: Optional[int] = None) -> dict:
        """
        Generate public and private keys of Brakerski-Vaikuntanathan cryptosystem
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
                f"Key size {d} must be a power of 2 and at least 8 for Brakerski-Vaikuntanathan"
            )

        q = Q
        t = 1 << DEFAULT_LOG_T
        if plaintext_limit is not None:
            if plaintext_limit < 2:
                raise ValueError("Plaintext limit must be at least 2")
            t = 1 << (plaintext_limit - 1).bit_length()

        # product of two fresh ciphertexts must be decrypted correctly
        multiplied_noise = self.__multiplied_noise_bound(d=d, t=t)
        if multiplied_noise >= q // 2:
            raise ValueError(
                f"Plaintext limit {plaintext_limit} is too large for Brakerski-Vaikuntanathan,"
                " because product of two ciphertexts cannot be decrypted correctly."
            )
        logger.debug(
            f"noise of multiplied ciphertexts can grow {(q // 2) / multiplied_noise:.0f} times"
        )

        seed = secrets.randbits(256)
        a = self.__expand(seed=seed, d=d)
        s = self.__sample_small(d)
        e = self.__sample_small(d)

        # b = -(a s + t e)
        a_s = self.__poly_mul(a, [x % q for x in s], d)
        b = [(-(x + t * y)) % q for x, y in zip(a_s, e)]

        keys["public_key"]["d"] = d
        keys["public_key"]["q"] = q
        keys["public_key"]["t"] = t
        keys["public_key"]["seed"] = seed
        keys["public_key"]["b"] = b

        keys["private_key"]["s"] = s

        return keys

    def generate_random_key(self) -> List[int]:
        """
        Brakerski-Vaikuntanathan requires a one-time small random polynomial per encryption
        Returns:
            random key (list): coefficients of small random polynomial u
        """
        return self.__sample_small(self.keys["public_key"]["d"])

    def encrypt(self, plaintext: int, random_key: Optional[List[int]] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Brakerski-Vaikuntanathan
        Args:
            plaintext (int): message to encrypt in [0, t)
            random_key (list): coefficients of small random polynomial u
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): pair of polynomials c0 = b u + t g + m and c1 = a u + t f
        """
        d = self.keys["public_key"]["d"]
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]
        b = self.keys["public_key"]["b"]
        u = random_key or self.generate_random_key()

        if plaintext >= t:
            plaintext = plaintext % t
            logger.debug(
                f"Brakerski-Vaikuntanathan can encrypt messages [0, {t}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        if self.__a is None:
            self.__a = self.__expand(seed=self.keys["public_key"]["seed"], d=d)

        u_mod_q = [x % q for x in u]
        f = self.__sample_small(d)
        g = self.__sample_small(d)

        c0 = [(x + t * y) % q for x, y in zip(self.__poly_mul(b, u_mod_q, d), g)]
        c0[0] = (c0[0] + plaintext) % q
        c1 = [(x + t * y) % q for x, y in zip(self.__poly_mul(self.__a, u_mod_q, d), f)]
        return tuple(c0), tuple(c1)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Brakerski-Vaikuntanathan
        Args:
            ciphertext (tuple): pair or triple of polynomials
        Returns:
            plaintext (int): restored message
        """
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]
        s = self.keys["private_key"]["s"]

        if len(ciphertext) not in [FRESH_SIZE, MULTIPLIED_SIZE]:
            raise ValueError("Ciphertext must be a pair or triple of polynomials")

        # only the constant term carries the message: c0 + c1 s (+ c2 s^2)
        result = ciphertext[0][0] + self.__constant_term(ciphertext[1], s)
        if len(ciphertext) == MULTIPLIED_SIZE:
            if self.__s_square is None:
                d = self.keys["public_key"]["d"]
                s_mod_q = [x % q for x in s]
                self.__s_square = self.__poly_mul(s_mod_q, s_mod_q, d)
            result += self.__constant_term(ciphertext[2], self.__s_square)

        # centered representative is m + t * noise
        result %= q
        if result > q // 2:
            result -= q
        return result % t

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Fresh and multiplied ciphertexts can be added.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Brakerski-Vaikuntanathan
            ciphertext2 (tuple): 2nd ciphertext created with Brakerski-Vaikuntanathan
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Brakerski-Vaikuntanathan
        """
        q = self.keys["public_key"]["q"]
        d = self.keys["public_key"]["d"]
        size = max(len(ciphertext1), len(ciphertext2))
        zero = (0,) * d
        first = tuple(ciphertext1) + (zero,) * (size - len(ciphertext1))
        second = tuple(ciphertext2) + (zero,) * (size - len(ciphertext2))
        return tuple(
            tuple((x + y) % q for x, y in zip(poly1, poly2))
            for poly1, poly2 in zip(first, second)
        )

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic multiplication on encrypted data.
        Result of this must be equal to E(m1 * m2).
        Only fresh ciphertexts (or sums of them) can be multiplied.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Brakerski-Vaikuntanathan
            ciphertext2 (tuple): 2nd ciphertext created with Brakerski-Vaikuntanathan
        Returns:
            ciphertext3 (tuple): triple of polynomials
        """
        if len(ciphertext1) != FRESH_SIZE or len(ciphertext2) != FRESH_SIZE:
            raise ValueError(
                "Brakerski-Vaikuntanathan supports only one multiplication. "
                "Multiplied ciphertexts cannot be multiplied with ciphertexts again."
            )
        q = self.keys["public_key"]["q"]
        d = self.keys["public_key"]["d"]
        c0, c1 = ciphertext1
        c0_prime, c1_prime = ciphertext2

        # Karatsuba: c0 c1' + c1 c0' = (c0 + c1)(c0' + c1') - c0 c0' - c1 c1'
        low = self.__poly_mul(c0, c0_prime, d)
        high = self.__poly_mul(c1, c1_prime, d)
        cross = self.__poly_mul(
            [(x + y) % q for x, y in zip(c0, c1)],
            [(x + y) % q for x, y in zip(c0_prime, c1_prime)],
            d,
        )
        middle = [(x - y - z) % q for x, y, z in zip(cross, low, high)]
        return tuple(low), tuple(middle), tuple(high)

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Noise of the result is the noise of the ciphertext times |constant|.
        Args:
            ciphertext (tuple): ciphertext created with Brakerski-Vaikuntanathan
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Brakerski-Vaikuntanathan
        """
        q = self.keys["public_key"]["q"]
        t = self.keys["public_key"]["t"]

        # centered representative keeps the noise small for negative constants.
        # it is congruent to the constant mod t, so the result does not change.
        constant = constant % t
        if constant > t // 2:
            constant -= t

        return tuple(tuple((x * constant) % q for x in poly) for poly in ciphertext)

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
        return [(coefficients[i] - coefficients[i + d]) % Q for i in range(d)]

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
        Expand the public polynomial a from its seed with SHAKE-128. Each coefficient is
            reduced from 64 more bits than q, so it is statistically uniform in [0, q).
        """
        width = math.ceil((LOG_Q + 64) / 8)
        stream = hashlib.shake_128(seed.to_bytes(32, "big")).digest(d * width)
        return [
            int.from_bytes(stream[i * width : (i + 1) * width], "little") % Q for i in range(d)
        ]

    @staticmethod
    def __multiplied_noise_bound(d: int, t: int) -> int:
        """
        Bound of the noise in the product of two fresh ciphertexts. A fresh ciphertext
            decrypts to m + t v where v = g + f s - e u, whose coefficients have standard
            deviation about sigma^2 sqrt(2d). The product multiplies two such polynomials,
            whose constant term sums d products of coefficients.
        """
        variance = ETA / 2
        fresh_deviation = t * (variance * math.sqrt(2 * d) + 1)
        return math.ceil(NOISE_TAIL * math.sqrt(d) * fresh_deviation**2)
