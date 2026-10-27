# built-in dependencies
import hashlib
import secrets
from typing import Optional, List

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/MLKEM.py")

# pylint: disable=too-many-nested-blocks

# floats are scaled by powers of 10, and xor of their encodings is meaningless
FLOAT_NOT_SUPPORTED_MSG = (
    "ML-KEM does not support float values or tensors, because it is homomorphic with"
    " respect to the exclusive or of 256-bit messages. Use integers instead."
)

# parameters of FIPS 203: ring Z_q[x] / (x^N + 1) with q = 3329 and N = 256
Q = 3329
N = 256

# parameter sets of FIPS 203: module rank k, and parameters of centered binomial
# distributions for secret and error vectors (eta1) and errors of encryption (eta2)
PARAMETER_SETS = {
    512: {"k": 2, "eta1": 3, "eta2": 2},
    768: {"k": 3, "eta1": 2, "eta2": 2},
    1024: {"k": 4, "eta1": 2, "eta2": 2},
}

# bits of a message are encoded as 0 or round(q / 2)
HALF_Q = (Q + 1) // 2


class MLKEM(Homomorphic):
    """
    ML-KEM algorithm is homomorphic with respect to the exclusive or of 256-bit messages,
    like Goldwasser-Micali, but it is quantum resistant. It uses the parameter sets
    standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and ML-KEM-1024. Its security
    relies on the module learning with errors (Module-LWE) problem.

    ML-KEM is a key encapsulation mechanism built on a public key encryption scheme K-PKE.
    This is K-PKE, which works in modules of rank k over the ring R_q = Z_q[x] / (x^256 + 1).
        - private key: vector s of k polynomials with small coefficients
        - public key: k x k matrix A of polynomials and t = A s + e, where e is small
        - encryption of 256 message bits m_i: u = A^T r + e1, and v = t^T r + e2 + m q / 2
            where m q / 2 is the polynomial whose i-th coefficient is m_i * round(q / 2)
        - decryption: v - s^T u = m q / 2 + noise, so m_i is 1 if the i-th coefficient is
            closer to q / 2 than to 0
        - exclusive or: adding ciphertexts adds the bits modulo 2
    A is expanded from a public seed with SHAKE-128, so the public key is the seed and t.

    Notice that this is not a FIPS 203 compliant implementation of ML-KEM:
        - It is the CPA secure K-PKE, without the Fujisaki-Okamoto transform of ML-KEM that
            makes it CCA secure, because a CCA secure scheme cannot be homomorphic.
        - Ciphertexts are not compressed, because compression adds rounding noise that
            leaves no room for homomorphic operations. Security of K-PKE does not depend on
            compression, which only drops information from ciphertexts.
        - Byte encodings, the sampling of A and the NTT representation are not the ones in
            FIPS 203, so its keys and ciphertexts are not interoperable with other libraries.
        - It is not validated by NIST under FIPS 140-3.
    It uses the standardized parameters q, n, k, eta1 and eta2 only.

    key_size is the parameter set: 512, 768 or 1024. Default is 768, i.e. ML-KEM-768,
    which NIST categorizes as at least as hard to break as AES-192.

    Every ciphertext has noise, and exclusive or adds the noises of ciphertexts. Decryption
    returns a wrong result without any error when the noise exceeds q / 4. Fresh ciphertexts
    practically never fail, but q is small, so only a few ciphertexts can be combined.
    Failure probability of decrypting the exclusive or of c ciphertexts of ML-KEM-768 is
    about 2^-77 for c = 4, 2^-50 for c = 6, and 2^-36 for c = 8. Regenerating a ciphertext
    counts as combining it with one more ciphertext.
    Ciphertexts have k + 1 polynomials of 256 coefficients of 12 bits, about 1.5 KB for
    ML-KEM-768. Floats and tensors are not supported.

    Ref: National Institute of Standards and Technology (2024). Module-Lattice-Based
        Key-Encapsulation Mechanism Standard. FIPS 203.
    Ref: Bos, J. et al. (2018). CRYSTALS - Kyber: a CCA-secure module-lattice-based KEM.
        IEEE EuroS&P 2018.
    """

    REQUIRED_KEYS = {
        "public_key": ["parameter_set", "seed", "t"],
        "private_key": ["s"],
    }

    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): parameter set, 512, 768 or 1024. Default is 768.
        """
        self.keys = keys or self.generate_keys(key_size=key_size or 768)
        self.plaintext_modulo = 1 << N
        self.ciphertext_modulo = Q
        # A expanded from the seed when needed
        self.__a: Optional[List[List[List[int]]]] = None

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of ML-KEM's K-PKE
        Args:
            key_size (int): parameter set, 512, 768 or 1024
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        if key_size not in PARAMETER_SETS:
            raise ValueError(
                f"Key size {key_size} must be one of the parameter sets of ML-KEM:"
                f" {list(PARAMETER_SETS)}"
            )
        k = PARAMETER_SETS[key_size]["k"]
        eta1 = PARAMETER_SETS[key_size]["eta1"]

        seed = secrets.randbits(256)
        a = self.__expand(seed=seed, k=k)
        s = [self.__sample_small(eta1) for _ in range(k)]
        e = [self.__sample_small(eta1) for _ in range(k)]

        # t = A s + e
        t = []
        for i in range(k):
            row = [self.__poly_mul(a[i][j], s[j]) for j in range(k)]
            t.append(
                [(sum(column) + e[i][x]) % Q for x, column in enumerate(zip(*row))]
            )

        keys["public_key"]["parameter_set"] = key_size
        keys["public_key"]["seed"] = seed
        keys["public_key"]["t"] = t

        keys["private_key"]["s"] = s

        return keys

    def generate_random_key(self) -> List[List[int]]:
        """
        ML-KEM requires a one-time small random vector of polynomials per encryption
        Returns:
            random key (list): k polynomials r with small coefficients
        """
        parameters = PARAMETER_SETS[self.keys["public_key"]["parameter_set"]]
        return [self.__sample_small(parameters["eta1"]) for _ in range(parameters["k"])]

    def encrypt(
        self, plaintext: int, random_key: Optional[List[List[int]]] = None
    ) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with ML-KEM's K-PKE
        Args:
            plaintext (int): message to encrypt in [0, 2^256)
            random_key (list): k polynomials r with small coefficients
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): k polynomials of u = A^T r + e1, and v = t^T r + e2 + m q / 2
        """
        parameters = PARAMETER_SETS[self.keys["public_key"]["parameter_set"]]
        k = parameters["k"]
        t = self.keys["public_key"]["t"]
        r = random_key or self.generate_random_key()

        if plaintext >= self.plaintext_modulo:
            plaintext = plaintext % self.plaintext_modulo
            logger.debug(
                f"ML-KEM can encrypt messages [0, 2^{N}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        if self.__a is None:
            self.__a = self.__expand(seed=self.keys["public_key"]["seed"], k=k)

        e1 = [self.__sample_small(parameters["eta2"]) for _ in range(k)]
        e2 = self.__sample_small(parameters["eta2"])

        # u = A^T r + e1
        u = []
        for i in range(k):
            row = [self.__poly_mul(self.__a[j][i], r[j]) for j in range(k)]
            u.append(
                tuple(
                    (sum(column) + e1[i][x]) % Q for x, column in enumerate(zip(*row))
                )
            )

        # v = t^T r + e2 + m q / 2
        products = [self.__poly_mul(t[j], r[j]) for j in range(k)]
        v = tuple(
            (sum(column) + e2[x] + ((plaintext >> x) & 1) * HALF_Q) % Q
            for x, column in enumerate(zip(*products))
        )
        return tuple(u) + (v,)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with ML-KEM's K-PKE
        Args:
            ciphertext (tuple): k polynomials of u, and v
        Returns:
            plaintext (int): restored message
        """
        s = self.keys["private_key"]["s"]
        *u, v = ciphertext

        # v - s^T u = m q / 2 + noise
        products = [self.__poly_mul(u[j], s[j]) for j in range(len(u))]
        plaintext = 0
        for x, column in enumerate(zip(*products)):
            w = (v[x] - sum(column)) % Q
            # bit is 1 if w is closer to q / 2 than to 0
            if Q // 4 < w < Q - Q // 4:
                plaintext |= 1 << x
        return plaintext

    def xor(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic exclusive or on encrypted data.
        Result of this must be equal to E(m1 ^ m2)
        Noise of the result is the sum of noises of the ciphertexts.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with ML-KEM
            ciphertext2 (tuple): 2nd ciphertext created with ML-KEM
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with ML-KEM
        """
        # bits are added modulo 2, as 2 * round(q / 2) = q + 1 is close to 0 modulo q
        return tuple(
            tuple((x + y) % Q for x, y in zip(poly1, poly2))
            for poly1, poly2 in zip(ciphertext1, ciphertext2)
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

    @staticmethod
    def __poly_mul(poly1: List[int], poly2: List[int]) -> List[int]:
        """
        Multiply two polynomials in Z_q[x] / (x^256 + 1) with Kronecker substitution.
            Coefficients are packed into big integers, so that a single big integer
            multiplication computes all coefficients of the product, which is much faster
            than multiplying coefficients one by one in Python. Small coefficients may be
            negative, so they are reduced modulo q first.
        Args:
            poly1 (list): 256 coefficients
            poly2 (list): 256 coefficients
        Returns:
            product (list): 256 coefficients in [0, q)
        """
        # each coefficient of the product is a sum of 256 products less than q^2
        width = 5
        packed1 = int.from_bytes(
            b"".join((x % Q).to_bytes(width, "little") for x in poly1), "little"
        )
        packed2 = int.from_bytes(
            b"".join((x % Q).to_bytes(width, "little") for x in poly2), "little"
        )
        product = (packed1 * packed2).to_bytes(2 * N * width, "little")
        coefficients = [
            int.from_bytes(product[i * width : (i + 1) * width], "little")
            for i in range(2 * N)
        ]
        # x^256 = -1
        return [(coefficients[i] - coefficients[i + N]) % Q for i in range(N)]

    @staticmethod
    def __sample_small(eta: int) -> List[int]:
        """
        Sample a polynomial from centered binomial distribution with cryptographically
            secure randomness
        Args:
            eta (int): parameter of the distribution
        Returns:
            coefficients (list): 256 integers in [-eta, eta]
        """
        mask = (1 << eta) - 1
        samples = []
        for _ in range(N):
            bits = secrets.randbits(2 * eta)
            samples.append(bin(bits & mask).count("1") - bin(bits >> eta).count("1"))
        return samples

    @staticmethod
    def __expand(seed: int, k: int) -> List[List[List[int]]]:
        """
        Expand the public matrix A from its seed with SHAKE-128. Every 3 bytes give two
            12-bit values, which are accepted if they are less than q, so coefficients are
            uniform in [0, q). Each entry of A has its own stream.
        Args:
            seed (int): public seed
            k (int): module rank
        Returns:
            A (list): k x k polynomials
        """
        a = []
        for i in range(k):
            row = []
            for j in range(k):
                xof = hashlib.shake_128(seed.to_bytes(32, "big") + bytes([j, i]))
                coefficients: List[int] = []
                length = 3 * N
                while len(coefficients) < N:
                    stream = xof.digest(length)
                    coefficients = []
                    for x in range(0, length - 2, 3):
                        d1 = stream[x] | ((stream[x + 1] & 0x0F) << 8)
                        d2 = (stream[x + 1] >> 4) | (stream[x + 2] << 4)
                        for d in [d1, d2]:
                            if d < Q and len(coefficients) < N:
                                coefficients.append(d)
                    length *= 2
                row.append(coefficients)
            a.append(row)
        return a
