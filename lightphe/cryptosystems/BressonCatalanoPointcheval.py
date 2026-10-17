# built-in dependencies
import random
import math
from typing import Optional

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.safe_primes import find_safe_prime
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/BressonCatalanoPointcheval.py")

class BressonCatalanoPointcheval(Homomorphic):
    """
    Bresson-Catalano-Pointcheval algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    It is an ElGamal-like scheme in Z_{n^2}* with a double trapdoor decryption mechanism.
    A ciphertext can be decrypted either with the secret exponent a (local trapdoor),
    or with the factorization of n (master trapdoor) without knowing a.
    An authority holding the master key publishes n and g, then every user generates
    its own key pair on top of them. The authority can decrypt ciphertexts of all
    those users, so this is a key escrow mechanism by design.
    Ref: Bresson, E., Catalano, D., Pointcheval, D. (2003). A Simple Public-Key Cryptosystem
        with a Double Trapdoor Decryption Mechanism and Its Applications. ASIACRYPT 2003.
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "g", "h"],
        "private_key": ["a"],
        # authority may keep the master trapdoor only
        "alternative_private_key": ["p", "q"],
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
        n = self.keys["public_key"]["n"]
        self.plaintext_modulo = n
        self.ciphertext_modulo = n * n

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Bresson-Catalano-Pointcheval cryptosystem
        Args:
            key_size (int): key size in bits
            max_tries (int): maximum number of tries to generate keys
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        if key_size < 16:
            raise ValueError(
                f"Key size {key_size} is too small for Bresson-Catalano-Pointcheval"
            )

        # p = 2p' + 1 and q = 2q' + 1 are safe primes
        prime_size = key_size // 2
        p = find_safe_prime(bits=prime_size, max_tries=max_tries)
        q = find_safe_prime(bits=prime_size, max_tries=max_tries)
        while q == p:
            q = find_safe_prime(bits=prime_size, max_tries=max_tries)

        n = p * q
        n_square = n * n
        p_prime = (p - 1) // 2
        q_prime = (q - 1) // 2

        # g is a square in Z_{n^2}* of maximal order, so that g^(p'q') = 1 + kn mod n^2
        # for some k co-prime to n. k is required by the master trapdoor.
        for _ in range(max_tries):
            alpha = random.randint(2, n_square - 1)
            if math.gcd(alpha, n) != 1:
                continue
            g = pow(alpha, 2, n_square)
            k = (pow(g, p_prime * q_prime, n_square) - 1) // n
            if (
                math.gcd(k, n) == 1
                and pow(g, p_prime, n) != 1
                and pow(g, q_prime, n) != 1
            ):
                break
        else:
            raise ValueError(f"Failed to find a suitable generator in {max_tries} tries")

        # local trapdoor
        a = random.randint(1, n_square // 2)
        h = pow(g, a, n_square)

        keys["public_key"]["n"] = n
        keys["public_key"]["g"] = g
        keys["public_key"]["h"] = h

        keys["private_key"]["a"] = a
        # master trapdoor
        keys["private_key"]["p"] = p
        keys["private_key"]["q"] = q

        return keys

    def generate_user_keys(self) -> dict:
        """
        Generate a key pair for a new user sharing n and g of this cryptosystem.
            It requires the public key only. The private key of the new user has
            its local trapdoor a only, not the master trapdoor.
        Returns:
            keys (dict): having private_key and public_key keys
        """
        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        n_square = n * n
        a = random.randint(1, n_square // 2)
        return {
            "public_key": {"n": n, "g": g, "h": pow(g, a, n_square)},
            "private_key": {"a": a},
        }

    def generate_random_key(self) -> int:
        """
        Bresson-Catalano-Pointcheval requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        return random.randint(1, n * n - 1)

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Bresson-Catalano-Pointcheval
        Args:
            plaintext (int): message to encrypt in [0, n)
            random_key (int): Bresson-Catalano-Pointcheval requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): A = g^r mod n^2 and B = h^r (1 + mn) mod n^2
        """
        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        h = self.keys["public_key"]["h"]
        n_square = n * n
        r = random_key or self.generate_random_key()

        if plaintext >= n:
            plaintext = plaintext % n
            logger.debug(
                f"Bresson-Catalano-Pointcheval can encrypt messages [0, {n}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        a_part = pow(g, r, n_square)
        b_part = (pow(h, r, n_square) * (1 + plaintext * n)) % n_square
        return a_part, b_part

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Bresson-Catalano-Pointcheval using the local trapdoor a
        Args:
            ciphertext (tuple): encrypted message
        Returns:
            plaintext (int): restored message
        """
        if "a" not in self.keys["private_key"]:
            raise ValueError(
                "Private key does not have the local trapdoor a. "
                "Use decrypt_with_master_key if you have the master key."
            )

        n = self.keys["public_key"]["n"]
        a = self.keys["private_key"]["a"]
        n_square = n * n
        a_part, b_part = ciphertext

        # B / A^a = (1 + mn) mod n^2
        restored = (b_part * pow(pow(a_part, a, n_square), -1, n_square)) % n_square
        return self.__lx(restored)

    def decrypt_with_master_key(
        self, ciphertext: tuple, public_key: Optional[dict] = None
    ) -> int:
        """
        Decrypt a given ciphertext with Bresson-Catalano-Pointcheval using the master trapdoor,
            which is the factorization of n. It does not require the local trapdoor a, so
            the master key can decrypt ciphertexts of any key pair sharing the same n and g.
        Args:
            ciphertext (tuple): encrypted message
            public_key (dict): public key of the user who the ciphertext was encrypted for.
                Public key of this cryptosystem is used if you do not set this.
        Returns:
            plaintext (int): restored message
        """
        private_key = self.keys.get("private_key") or {}
        if "p" not in private_key or "q" not in private_key:
            raise ValueError("Private key does not have the master trapdoor p and q")

        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        public_key = public_key or self.keys["public_key"]
        if public_key["n"] != n or public_key["g"] != g:
            raise ValueError(
                "Ciphertext was not encrypted for a user of this master key "
                "as it does not share the same n and g"
            )
        h = public_key["h"]
        p = self.keys["private_key"]["p"]
        q = self.keys["private_key"]["q"]
        n_square = n * n
        order = ((p - 1) // 2) * ((q - 1) // 2)
        a_part, b_part = ciphertext

        # g^(p'q') = 1 + kn, so x^(p'q') = 1 + (log_g x) k n for any power x of g
        k_inv = pow(self.__lx(pow(g, order, n_square)), -1, n)
        a_mod_n = (self.__lx(pow(h, order, n_square)) * k_inv) % n
        r_mod_n = (self.__lx(pow(a_part, order, n_square)) * k_inv) % n
        gamma = (a_mod_n * r_mod_n) % n

        # B / g^gamma = g^(n t) (1 + mn) for some t, and g^(n t p'q') = 1 mod n^2
        masked = (b_part * pow(pow(g, gamma, n_square), -1, n_square)) % n_square
        return (self.__lx(pow(masked, order, n_square)) * pow(order, -1, n)) % n

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Bresson-Catalano-Pointcheval
            ciphertext2 (tuple): 2nd ciphertext created with Bresson-Catalano-Pointcheval
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Bresson-Catalano-Pointcheval
        """
        n = self.keys["public_key"]["n"]
        n_square = n * n
        return (
            (ciphertext1[0] * ciphertext2[0]) % n_square,
            (ciphertext1[1] * ciphertext2[1]) % n_square,
        )

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Args:
            ciphertext (tuple): ciphertext created with Bresson-Catalano-Pointcheval
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Bresson-Catalano-Pointcheval
        """
        n = self.keys["public_key"]["n"]
        n_square = n * n

        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Bresson-Catalano-Pointcheval can encrypt messages [0, {n}). "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )

        return pow(ciphertext[0], constant, n_square), pow(ciphertext[1], constant, n_square)

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

    def __lx(self, x: int) -> int:
        """
        L function of Paillier-like schemes
        Args:
            x (int): some integer equal to 1 mod n
        Returns:
            lx (int): (x - 1) / n
        """
        n = self.keys["public_key"]["n"]
        return (x - 1) // n
