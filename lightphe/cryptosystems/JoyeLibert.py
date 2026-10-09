# built-in dependencies
import random
import math
from typing import Optional

# 3rd party dependencies
import sympy
from sympy import jacobi_symbol

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/JoyeLibert.py")

# floats are represented as dividend * divisor^-1 where divisor is a power of 10,
# but powers of 10 are not invertible in the plaintext space Z_{2^k}
FLOAT_NOT_SUPPORTED_MSG = (
    "Joye-Libert does not support float values because its plaintext space is Z_{2^k}"
    " where powers of 10 have no modular inverse. Use integers instead."
)


class JoyeLibert(Homomorphic):
    """
    Joye-Libert algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    It generalizes Goldwasser-Micali from 1 bit to k bit messages by using
    2^k-th power residue symbols, so messages live in Z_{2^k}.
    Ref: Joye, M., Libert, B. (2013). Efficient Cryptosystems from 2^k-th Power Residue Symbols.
        EUROCRYPT 2013. https://eprint.iacr.org/2013/435
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "y", "k"],
        "private_key": ["p"],
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
        self.plaintext_modulo = 2 ** self.keys["public_key"]["k"]
        self.ciphertext_modulo = self.keys["public_key"]["n"]

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Joye-Libert cryptosystem
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

        # message space is Z_{2^k}. p - 1 must be divisible by 2^k, and the remaining
        # part of p must be large enough to keep factoring n hard.
        k = max(1, key_size // 4)

        # picking a prime p such that p = 1 mod 2^k
        p = None
        for _ in range(max_tries):
            t = random.randint(2 ** (prime_size - k - 1), 2 ** (prime_size - k) - 1)
            p_candidate = t * 2**k + 1
            if sympy.isprime(p_candidate):
                p = p_candidate
                break

        if p is None:
            raise Exception(f"Failed to find prime p = 1 mod 2^{k} in {max_tries} tries")

        # picking a prime modulus q
        q = sympy.randprime(2 ** (prime_size - 1), 2**prime_size - 1)
        while q == p:
            q = sympy.randprime(2 ** (prime_size - 1), 2**prime_size - 1)

        n = p * q

        # y must be a quadratic non-residue modulo both p and q,
        # so y is in J_n \ QR_n (jacobi symbol 1 but not a square)
        for _ in range(max_tries):
            y = random.randint(2, n - 1)
            if math.gcd(y, n) != 1:
                continue
            if jacobi_symbol(y, p) == -1 and jacobi_symbol(y, q) == -1:
                break
        else:
            raise Exception(f"Failed to find suitable y in {max_tries} tries")

        keys["private_key"]["p"] = p
        keys["public_key"]["n"] = n
        keys["public_key"]["y"] = y
        keys["public_key"]["k"] = k

        return keys

    def generate_random_key(self) -> int:
        """
        Joye-Libert requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            x = random.randint(1, n - 1)
            if math.gcd(x, n) == 1:
                break
        return x

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with Joye-Libert
        Args:
            plaintext (int): message to encrypt in [0, 2^k)
            random_key (int): Joye-Libert requires a random key that co-prime to n.
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        n = self.keys["public_key"]["n"]
        y = self.keys["public_key"]["y"]
        k = self.keys["public_key"]["k"]
        x = random_key or self.generate_random_key()

        if plaintext >= self.plaintext_modulo:
            plaintext = plaintext % self.plaintext_modulo
            logger.debug(
                f"Joye-Libert can encrypt messages [0, {self.plaintext_modulo}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        return (pow(y, plaintext, n) * pow(x, 2**k, n)) % n

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a given ciphertext with Joye-Libert
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        p = self.keys["private_key"]["p"]
        y = self.keys["public_key"]["y"]
        k = self.keys["public_key"]["k"]
        exponent = (p - 1) >> k

        # z = D^m mod p where D = y^((p-1)/2^k) has order exactly 2^k,
        # so m can be restored bit by bit
        z = pow(ciphertext, exponent, p)
        d_inv = pow(pow(y, exponent, p), -1, p)

        m = 0
        b = 1
        for j in range(1, k):
            if pow(z, 2 ** (k - j), p) != 1:
                m += b
                z = (z * d_inv) % p
            b *= 2
            d_inv = (d_inv * d_inv) % p

        if z != 1:
            m += b

        return m

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (int): 1st ciphertext created with Joye-Libert
            ciphertext2 (int): 2nd ciphertext created with Joye-Libert
        Returns:
            ciphertext3 (int): 3rd ciphertext created with Joye-Libert
        """
        n = self.keys["public_key"]["n"]
        return (ciphertext1 * ciphertext2) % n

    def multiply_by_constant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * m2) where E(m1) = ciphertext
        Args:
            ciphertext (int): ciphertext created with Joye-Libert
            constant (int): known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Joye-Libert
        """
        n = self.keys["public_key"]["n"]

        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Joye-Libert can encrypt messages [0, {self.plaintext_modulo}). "
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
