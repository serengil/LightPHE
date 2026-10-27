# built-in dependencies
import math
import hashlib
import secrets
from typing import Optional, List

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/GentrySahaiWaters.py")

# floats, tensors and integers other than bits cannot be encrypted
FLOAT_NOT_SUPPORTED_MSG = (
    "Gentry-Sahai-Waters encrypts bits, i.e. 0 or 1, and it does not support float values,"
    " tensors or other integers. Encrypt integers bit by bit instead."
)

# ciphertext modulus q = 2^LOG_Q
LOG_Q = 50

# gadget decomposition in base B = 2^LOG_B with ELL digits. Gadget is approximate:
# its entries are 2^OFFSET, 2^OFFSET * B, ..., 2^OFFSET * B^(ELL - 1) = q / 2, so the lowest
# OFFSET bits are dropped by rounding, and decryption reads the parity of the message.
LOG_B = 10
ELL = 5
OFFSET = LOG_Q - 1 - LOG_B * (ELL - 1)

# secret and errors are sampled from centered binomial distribution with this parameter
# its standard deviation is sqrt(ETA / 2) = 3.24, and its values are in [-ETA, ETA]
ETA = 21


class GentrySahaiWaters(Homomorphic):
    """
    Gentry-Sahai-Waters algorithm encrypts bits, and it is homomorphic with respect to both
    the exclusive or and the and. Unlike Boneh-Goh-Nissim or Brakerski-Vaikuntanathan, it
    supports more than one multiplication, so boolean circuits of a small depth can be
    evaluated on encrypted bits. It is quantum resistant, and its security relies on the
    ring learning with errors (Ring-LWE) problem.

    This is the ring variant of GSW. It works in the polynomial ring R_q = Z_q[x] / (x^d + 1).
        - private key: polynomial s with small coefficients
        - public key: a and b = -(a s) + e, where e is a small error polynomial
        - an encryption of zero is (b u + e1, a u + e2), whose phase c0 + c1 s is small
        - encryption of a bit m: 2 * ELL encryptions of zero Z, and C = Z + m G, where G is
            the gadget matrix having powers of B in its first and second columns
        - decryption: phase of the last row is m q / 2 + noise, so m is restored by rounding
        - and: C1 x G^-1(C2) where G^-1 decomposes entries of C2 into small digits, so the
            noise of C2 is multiplied by small digits only
        - exclusive or: C1 + C2 encrypts m1 + m2, whose parity is restored by decryption
    a is expanded from a public seed with SHAKE-128, so the public key is the seed and b.

    key_size is the ring degree d, a power of 2. Default is 2048. With q = 2^50, degree
    2048 gives about 128-bit security against quantum attacks according to the tables
    of Homomorphic Encryption Standard (log q must be at most 51 for d = 2048).
    Smaller degrees are not secure, and are for testing only.

    Every ciphertext has noise. Exclusive or adds the noises of ciphertexts, so it is
    almost free. Noise of C1 & C2 is the noise of C2 times small digits plus the noise of
    C1, so it depends on the order of operands:
        - chains: acc = acc & c where c is a fresh ciphertext adds a fixed noise of about 2^17
            each time, so long chains of ands, e.g. carries of a ripple carry adder, work.
        - products of products: noise is multiplied by about 2^15 in each level, so
            circuits of multiplicative depth 2 work, e.g. (a & b) & (c & d), but depth 3
            does not. Decryption returns a wrong result without any error when the noise
            exceeds q / 4 = 2^48. Fresh noise is about 2^10.
    Encrypting a bit takes about 0.5 seconds and an and takes about 1.2 seconds for the
    default degree. Ciphertexts have 2 * ELL x 2 polynomials of d coefficients of 50 bits,
    about 256 KB for d = 2048. Floats, tensors and integers other than bits are not supported.

    Ref: Gentry, C., Sahai, A., Waters, B. (2013). Homomorphic Encryption from Learning with
        Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based. CRYPTO 2013.
    Ref: Ducas, L., Micciancio, D. (2015). FHEW: Bootstrapping Homomorphic Encryption in
        less than a second. EUROCRYPT 2015.
    Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
        HomomorphicEncryption.org.
    """

    REQUIRED_KEYS = {
        "public_key": ["d", "q", "seed", "b"],
        "private_key": ["s"],
    }

    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): ring degree, a power of 2. Default is 2048.
        """
        self.keys = keys or self.generate_keys(key_size=key_size or 2048)
        self.plaintext_modulo = 2
        self.ciphertext_modulo = self.keys["public_key"]["q"]
        # a expanded from the seed when needed
        self.__a: Optional[List[int]] = None

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of Gentry-Sahai-Waters cryptosystem
        Args:
            key_size (int): ring degree
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        d = key_size
        if d < 8 or d & (d - 1) != 0:
            raise ValueError(
                f"Key size {d} must be a power of 2 and at least 8 for Gentry-Sahai-Waters"
            )

        q = 1 << LOG_Q
        seed = secrets.randbits(256)
        a = self.__expand(seed=seed, d=d)
        s = self.__sample_small(d)
        e = self.__sample_small(d)

        # b = -(a s) + e
        a_s = self.__poly_mul(a, [x % q for x in s], d)
        b = [(-x + y) % q for x, y in zip(a_s, e)]

        keys["public_key"]["d"] = d
        keys["public_key"]["q"] = q
        keys["public_key"]["seed"] = seed
        keys["public_key"]["b"] = b

        keys["private_key"]["s"] = s

        return keys

    def generate_random_key(self) -> List[List[int]]:
        """
        Gentry-Sahai-Waters requires a one-time small random polynomial for each row
        Returns:
            random key (list): 2 * ELL small random polynomials u
        """
        d = self.keys["public_key"]["d"]
        return [self.__sample_small(d) for _ in range(2 * ELL)]

    def encrypt(self, plaintext: int, random_key: Optional[List[List[int]]] = None) -> tuple:
        """
        Encrypt a given bit for optionally given random key with Gentry-Sahai-Waters
        Args:
            plaintext (int): bit to encrypt, 0 or 1
            random_key (list): 2 * ELL small random polynomials u
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): 2 * ELL rows of polynomial pairs Z + m G
        """
        d = self.keys["public_key"]["d"]
        q = self.keys["public_key"]["q"]
        b = self.keys["public_key"]["b"]
        us = random_key or self.generate_random_key()

        if plaintext not in [0, 1]:
            plaintext = plaintext % 2
            logger.debug(
                "Gentry-Sahai-Waters can encrypt bits only. "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        if self.__a is None:
            self.__a = self.__expand(seed=self.keys["public_key"]["seed"], d=d)

        rows = []
        for i, u in enumerate(us):
            u_mod_q = [x % q for x in u]
            e1 = self.__sample_small(d)
            e2 = self.__sample_small(d)
            c0 = [(x + y) % q for x, y in zip(self.__poly_mul(b, u_mod_q, d), e1)]
            c1 = [(x + y) % q for x, y in zip(self.__poly_mul(self.__a, u_mod_q, d), e2)]

            # first ELL rows carry m g_i in c0, and last ELL rows carry it in c1
            if i < ELL:
                c0[0] = (c0[0] + plaintext * self.__gadget(i)) % q
            else:
                c1[0] = (c1[0] + plaintext * self.__gadget(i - ELL)) % q
            rows.append((tuple(c0), tuple(c1)))
        return tuple(rows)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Gentry-Sahai-Waters
        Args:
            ciphertext (tuple): 2 * ELL rows of polynomial pairs
        Returns:
            plaintext (int): restored bit
        """
        q = self.keys["public_key"]["q"]
        s = self.keys["private_key"]["s"]

        # phase of the last row of the first half is m q / 2 + noise
        c0, c1 = ciphertext[ELL - 1]
        phase = (c0[0] + self.__constant_term(c1, s)) % q
        return 1 if q // 4 <= phase < q - q // 4 else 0

    def homomorphic_and(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic and on encrypted bits.
        Result of this must be equal to E(m1 & m2)
        Noise of the result is the noise of ciphertext2 times small digits plus the noise
        of ciphertext1, so keep ciphertext2 fresh in long chains, e.g. acc = acc & fresh.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Gentry-Sahai-Waters
            ciphertext2 (tuple): 2nd ciphertext created with Gentry-Sahai-Waters
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Gentry-Sahai-Waters
        """
        return self.__product(ciphertext1, ciphertext2)

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic multiplication on encrypted bits, which is the and of them.
        Result of this must be equal to E(m1 * m2)
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Gentry-Sahai-Waters
            ciphertext2 (tuple): 2nd ciphertext created with Gentry-Sahai-Waters
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Gentry-Sahai-Waters
        """
        return self.__product(ciphertext1, ciphertext2)

    def xor(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic exclusive or on encrypted bits.
        Result of this must be equal to E(m1 ^ m2)
        Sum of ciphertexts encrypts m1 + m2, and decryption restores its parity.
        Noise of the result is the sum of noises of the ciphertexts.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Gentry-Sahai-Waters
            ciphertext2 (tuple): 2nd ciphertext created with Gentry-Sahai-Waters
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Gentry-Sahai-Waters
        """
        q = self.keys["public_key"]["q"]
        return tuple(
            tuple(
                tuple((x + y) % q for x, y in zip(poly1, poly2))
                for poly1, poly2 in zip(row1, row2)
            )
            for row1, row2 in zip(ciphertext1, ciphertext2)
        )

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
        return self.xor(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    def __product(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Compute G^-1(C1) x C2, i.e. each row of C1 is decomposed into 2 * ELL small digit
            polynomials, and the row of the result is their weighted sum of rows of C2.
            Its phase is G^-1(C1) x noise of C2 + m2 * phase of C1, so it encrypts m1 m2.
            Digits are shifted by B / 2 to be non-negative for packing, and the shift is
            subtracted afterwards.
        Args:
            ciphertext1 (tuple): 1st ciphertext
            ciphertext2 (tuple): 2nd ciphertext
        Returns:
            product (tuple): 2 * ELL rows of polynomial pairs
        """
        d = self.keys["public_key"]["d"]
        q = self.keys["public_key"]["q"]
        half_b = 1 << (LOG_B - 1)

        # each coefficient sums 2 * ELL * d products of a digit less than B and an entry of C2
        width = math.ceil((LOG_Q + LOG_B + (2 * ELL * d).bit_length() + 1) / 8)
        packed2 = [[self.__pack(poly, width) for poly in row] for row in ciphertext2]

        # shift adds (B / 2) J to digits where J is the all ones polynomial, so
        # (B / 2) J times the sum of rows of C2 is subtracted from every row of the result.
        # (J c)_i = sum of c_j for j <= i minus sum of c_j for j > i
        corrections = []
        for column in range(2):
            total = [sum(row[column][i] for row in ciphertext2) for i in range(d)]
            whole = sum(total)
            prefix = 0
            correction = []
            for x in total:
                prefix += x
                correction.append(half_b * (2 * prefix - whole))
            corrections.append(correction)

        rows = []
        for row in ciphertext1:
            digits = self.__decompose(row[0]) + self.__decompose(row[1])
            accumulators = [0, 0]
            for digit, packed_row in zip(digits, packed2):
                packed_digit = self.__pack([x + half_b for x in digit], width)
                accumulators[0] += packed_digit * packed_row[0]
                accumulators[1] += packed_digit * packed_row[1]
            rows.append(
                tuple(
                    tuple(
                        (x - y) % q
                        for x, y in zip(self.__unpack(accumulator, d, width), correction)
                    )
                    for accumulator, correction in zip(accumulators, corrections)
                )
            )
        return tuple(rows)

    @staticmethod
    def __gadget(index: int) -> int:
        """
        Entry of the approximate gadget, 2^OFFSET * B^index
        """
        return 1 << (OFFSET + LOG_B * index)

    @staticmethod
    def __decompose(poly: List[int]) -> List[List[int]]:
        """
        Decompose a polynomial into ELL polynomials of signed digits in [-B / 2, B / 2), so
            that sum of digits_i * gadget_i is the polynomial up to a rounding error less
            than 2^OFFSET in each coefficient.
        Args:
            poly (list): d coefficients in [0, q)
        Returns:
            digits (list): ELL polynomials
        """
        q = 1 << LOG_Q
        base = 1 << LOG_B
        half_b = base >> 1
        digits: List[List[int]] = [[] for _ in range(ELL)]
        for x in poly:
            # centered representative, rounded to a multiple of 2^OFFSET
            x = x - q if x >= q >> 1 else x
            x = (x + (1 << (OFFSET - 1))) >> OFFSET
            for j in range(ELL):
                digit = x % base
                if digit >= half_b:
                    digit -= base
                digits[j].append(digit)
                x = (x - digit) >> LOG_B
        return digits

    @staticmethod
    def __pack(poly: List[int], width: int) -> int:
        """
        Pack non-negative coefficients into a big integer of width bytes per coefficient
        """
        return int.from_bytes(b"".join(x.to_bytes(width, "little") for x in poly), "little")

    @staticmethod
    def __unpack(packed: int, d: int, width: int) -> List[int]:
        """
        Unpack the product of two packed polynomials, and reduce it modulo x^d + 1
        """
        raw = packed.to_bytes(2 * d * width, "little")
        coefficients = [
            int.from_bytes(raw[i * width : (i + 1) * width], "little") for i in range(2 * d)
        ]
        # x^d = -1
        return [coefficients[i] - coefficients[i + d] for i in range(d)]

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
        q = 1 << LOG_Q
        width = math.ceil((2 * LOG_Q + d.bit_length()) / 8)
        packed1 = GentrySahaiWaters.__pack(poly1, width)
        packed2 = GentrySahaiWaters.__pack(poly2, width)
        return [x % q for x in GentrySahaiWaters.__unpack(packed1 * packed2, d, width)]

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
