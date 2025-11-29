# built-in dependencies
import random
from typing import Optional, List
import math

# 3rd party dependencies
import sympy
from sympy import jacobi_symbol
from tqdm import tqdm

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/GoldwasserMicali.py")

# pylint:disable=consider-using-enumerate


class GoldwasserMicali(Homomorphic):
    """
    Goldwasser-Micali algorithm is homomorphic with respect to the Exclusively OR (XOR).
    Ref: sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/
    """

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
        self.ciphertext_modulo = self.keys["public_key"]["n"]

        # Plaintext can be any integer (even larger than n) because it is internally
        # encrypted bit by bit. Internally, each bit uses modulo 2, but LightPHE expects
        # integers, not bits. The original integer can be fully restored after decryption
        # even if it is larger than n.
        self.plaintext_modulo = self.keys["public_key"]["n"]

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Goldwasser-Micali cryptosystem
        Args:
            key_size (int): key size in bits
            max_tries (int): maximum number of tries to generate keys
        Returns:
            keys (dict): having private_key and public_key keys
        """
        for attempt in tqdm(range(max_tries), disable=True):
            # pick large random primes p and q
            p = sympy.randprime(2 ** (key_size // 2 - 100), 2 ** (key_size // 2) - 1)
            q = sympy.randprime(2 ** (key_size // 2 - 100), 2 ** (key_size // 2) - 1)

            # to prevent factorizatin attacks, it is recommended that n should be
            # several hundred bits or more
            n = p * q

            # find quadratic non-residue x
            for _ in range(1000):  # try max 1000 random x
                x = random.randint(2, n - 1)
                if math.gcd(x, n) != 1:
                    continue
                if jacobi_symbol(x, p) == -1 and jacobi_symbol(x, q) == -1:
                    break
            else:
                # # If no suitable x is found after 1000 tries, discard the current p–q pair and retry
                continue

            keys = {
                "public_key": {"n": n, "x": x},
                "private_key": {"p": p, "q": q},
            }

            logger.debug(
                f"Goldwasser-Micali keys generated after {attempt+1} attempts, n bits: {n.bit_length()}"
            )

            return keys

        raise RuntimeError(
            f"Failed to generate Goldwasser-Micali keys after {max_tries} attempts."
            "Please try to rerun."
        )

    def generate_random_key(self) -> int:
        """
        Goldwasser-Micali requires to generate one-time random key that co-prime to n
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            r = random.randint(1, n)
            if math.gcd(r, n) == 1:
                break
        return r

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> List[int]:
        """
        Encrypt a given plaintext for optionally given random key with Goldwasser-Micali
        Args:
            plaintext (int): message to encrypt
            random_key (int): Goldwasser-Micali requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        n = self.keys["public_key"]["n"]
        x = self.keys["public_key"]["x"]

        m_binary = bin(plaintext)[2:]

        # number of bits
        k = len(m_binary)

        if random_key and len(random_key) != k:
            raise ValueError(f"Random key must be length of {k}")

        c = []
        for i in range(0, k):
            mi = int(m_binary[i])

            if random_key:
                ri = random_key[i]
            else:
                ri = self.generate_random_key()

            ci = (pow(ri, 2, n) * pow(x, mi, n)) % n
            c.append(ci)

        return c

    def decrypt(self, ciphertext: List[int]) -> int:
        """
        Decrypt a given ciphertext with Goldwasser-Micali
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        m_binaries = []

        p = self.keys["private_key"]["p"]
        q = self.keys["private_key"]["q"]

        for i in ciphertext:
            xp = i % p
            xq = i % q

            # reaches int limit for 3072-bit key
            # if pow(xp, int((p - 1) / 2), p) == 1 and pow(xq, int((q - 1) / 2), q) == 1:
            if (
                pow(xp, int((p - 1) // 2), p) == 1
                and pow(xq, int((q - 1) // 2), q) == 1
            ):
                m_binaries.append("0")
            else:
                m_binaries.append("1")

        m_binary = "".join(m_binaries)
        return int(m_binary, 2)

    def add(self, ciphertext1: list, ciphertext2: list) -> list:
        raise ValueError(
            "Goldwasser-Micali is not homomorphic with respect to the addition"
        )

    def multiply(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError(
            "Goldwasser-Micali is not homomorphic with respect to the multiplication"
        )

    def xor(self, ciphertext1: List[int], ciphertext2: List[int]) -> List[int]:
        """
        Perform homomorphic xor on encrypted data.
        Result of this must be equal to E(m1 ^ m2) = E(m1) ^ E(m2)
        Encryption calculations are done in module n
        Args:
            ciphertext1 (list of int): 1st ciphertext created with Goldwasser-Micali
            ciphertext2 (list of int): 2nd ciphertext created with Goldwasser-Micali
        Returns:
            ciphertext3 (list of int): 3rd ciphertext created with Goldwasser-Micali
        """
        if len(ciphertext1) > len(ciphertext2):
            ciphertext2 = [self.encrypt(0)[0]] * (
                len(ciphertext1) - len(ciphertext2)
            ) + ciphertext2
        elif len(ciphertext2) > len(ciphertext1):
            ciphertext1 = [self.encrypt(0)[0]] * (
                len(ciphertext2) - len(ciphertext1)
            ) + ciphertext1

        assert len(ciphertext1) == len(ciphertext2)

        ciphertext3 = []
        for i in range(0, len(ciphertext1)):
            c1 = ciphertext1[i]
            c2 = ciphertext2[i]

            ciphertext3.append((c1 * c2) % self.ciphertext_modulo)

        return ciphertext3
