# built-in dependencies
import math
import random
from typing import Optional, List

# third-party dependencies
import sympy
from sympy import jacobi_symbol

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger


logger = Logger(module="lightphe/cryptosystems/SanderYoungYung.py")


class SanderYoungYung(Homomorphic):
    """
    Sander-Young-Yung algorithm is homomorphic with respect to the addition.
    TODO: add a tutorial for this algorithm.
    """

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
            key_size (int): key size in bits
        """
        self.keys = keys or self.generate_keys(
            key_size or 1024, plaintext_limit=plaintext_limit
        )
        self.ciphertext_modulo = self.keys["public_key"]["n"]
        self.plaintext_modulo = self.keys["public_key"]["l"]

    def generate_keys(
        self,
        key_size: int,
        max_tries: int = 10000,
        plaintext_limit: Optional[int] = None,
    ) -> dict:
        """
        Generate public and private keys of Sander-Young-Yung cryptosystem
        Args:
            key_size (int): key size in bits
            max_tries (int): maximum number of attempts to find suitable keys

        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {
            "public_key": {},
            "private_key": {},
        }

        for _ in range(max_tries):
            # pick primes p and q
            p = sympy.randprime(2 ** (key_size // 2 - 100), 2 ** (key_size // 2) - 1)
            q = sympy.randprime(2 ** (key_size // 2 - 100), 2 ** (key_size // 2) - 1)

            # pick positive integer l
            if plaintext_limit is not None:
                l = random.randint(plaintext_limit, plaintext_limit + 100)
            else:
                l = random.randint(100, 200)

            n = p * q

            for _ in range(int(max_tries / 10)):
                x = random.randint(1, n - 1)
                if math.gcd(x, n) != 1:
                    continue
                if jacobi_symbol(x, p) != -1 or jacobi_symbol(x, q) != -1:
                    continue

                keys["public_key"]["n"] = n
                keys["public_key"]["x"] = x
                keys["public_key"]["l"] = l

                keys["private_key"]["p"] = p
                keys["private_key"]["q"] = q

                return keys

            # if we cannot find suitable x in max_tries/10 attempts, we can try different p and q
            continue

        raise Exception(f"Failed to find suitable key in {max_tries} tries")

    def generate_random_key(self) -> int:
        """
        Sander-Young-Yung requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            r = random.randint(0, n)
            if math.gcd(r, n) == 1:
                break
        return r

    def encrypt(self, plaintext: int) -> List[List[int]]:
        """
        Encrypt a given plaintext for optionally given random key with Sander-Young-Yung
        Args:
            plaintext (int): message to encrypt in binary format (0 or 1)
        Returns:
            ciphertexts (List[List[int]]): encrypted message as a list of lists of integers
        """
        ciphertexts = []

        n = self.keys["public_key"]["n"]
        l = self.keys["public_key"]["l"]
        x = self.keys["public_key"]["x"]

        m_binary = bin(plaintext)[2:]

        # number of bits
        k = len(m_binary)

        logger.debug(f"plaintext: {plaintext}, binary: {m_binary} ({k} bits)")

        for i in range(0, k):
            ciphertext = []
            mi = int(m_binary[i])

            logger.debug(f"Encrypting bit {i} of plaintext: {mi}")
            if mi == 1:
                vs = [0 for _ in range(l)]
                # vs: 1 is encoded as the zero vector in Z2^l
                for i in range(l):
                    yi = self.generate_random_key()
                    ci = (yi * yi) % n
                    ciphertext.append(ci)
            if mi == 0:
                while True:
                    vs = []
                    for i in range(l):
                        vi = random.randint(0, 1)
                        vs.append(vi)
                    if sum(vs) > 0:
                        break
                    # vs: 0 is encoded as a nonzero vector in Z2^l

                for i in range(l):
                    yi = self.generate_random_key()
                    ci = (yi * yi * pow(x, vs[i], n)) % n
                    ciphertext.append(ci)

            ciphertexts.append(ciphertext)

        return ciphertexts

    def decrypt(self, ciphertext: List[List[int]]) -> int:
        """
        Decrypt a given ciphertext with Sander-Young-Yung
        Args:
            ciphertext (List[List[int]]): encrypted message as a list of lists of integers
        Returns:
            plaintext (int): restored message in binary format (0 or 1)
        """
        p = self.keys["private_key"]["p"]
        q = self.keys["private_key"]["q"]
        l = self.keys["public_key"]["l"]
        plaintexts = []
        for ci in ciphertext:
            vs = []
            for i in range(l):
                if jacobi_symbol(ci[i], p) == 1 and jacobi_symbol(ci[i], q) == 1:
                    vi = 0
                else:
                    vi = 1
                vs.append(vi)
            plaintext = 1 if sum(vs) == 0 else 0
            plaintexts.append(plaintext)

        return int("".join(map(str, plaintexts)), 2)

    def homomorphic_and(
        self, ciphertext1: List[List[int]], ciphertext2: List[List[int]]
    ) -> List[List[int]]:
        if len(ciphertext1) > len(ciphertext2):
            pad = self.encrypt(plaintext=0)
            for _ in range(len(ciphertext1) - len(ciphertext2)):
                ciphertext2 = pad + ciphertext2
        if len(ciphertext2) > len(ciphertext1):
            pad = self.encrypt(plaintext=0)
            for _ in range(len(ciphertext2) - len(ciphertext1)):
                ciphertext1 = pad + ciphertext1

        c1_and_c2_list = []
        n = self.keys["public_key"]["n"]
        l = self.keys["public_key"]["l"]

        if len(ciphertext1) != len(ciphertext2):
            raise ValueError(
                f"Ciphertexts must have the same length but got {len(ciphertext1)} and {len(ciphertext2)}"
            )

        for c1, c2 in zip(ciphertext1, ciphertext2):
            if len(c1) != len(c2):
                raise ValueError(
                    f"Ciphertexts must have the same length but got {len(c1)} and {len(c2)}"
                )
            c1_and_c2 = [(c1[i] * c2[i]) % n for i in range(l)]
            c1_and_c2_list.append(c1_and_c2)
        return c1_and_c2_list

    def reencrypt(self, ciphertext: List[List[int]]) -> List[List[int]]:
        ciphertext_reencrypted = []
        l = self.keys["public_key"]["l"]
        for ci in ciphertext:
            r = [self.generate_random_key() for _ in range(l)]
            ci_reencrypted = [
                (ci[i] * r[i] * r[i]) % self.ciphertext_modulo for i in range(l)
            ]
            ciphertext_reencrypted.append(ci_reencrypted)
        return ciphertext_reencrypted
