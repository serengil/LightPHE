# built-in dependencies
import random
import decimal
from typing import Any, Optional, List, Tuple

# 3rd party dependencies
import sympy

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger
from lightphe.commons import threshold as threshold_utils
from lightphe.commons import zkp

logger = Logger(module="lightphe/cryptosystems/ElGamal.py")

DECRYPTION_DOMAIN = "lightphe/elgamal/decryption"
PARTIAL_DECRYPTION_DOMAIN = "lightphe/elgamal/partial-decryption"
MEMBERSHIP_DOMAIN = "lightphe/exponential-elgamal/membership"


class ElGamal(Homomorphic):
    """
    ElGamal algorithm is either multiplicatively or additively homomorphic
    Ref: https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/
    """

    REQUIRED_KEYS = {
        "public_key": ["p", "g", "y"],
        "private_key": ["x"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        exponential=False,
        key_size: Optional[int] = None,
        prime_order: bool = False,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
            exponential (boolean): set this to True to make cryptosystem exponential ElGamal.
                Regular ElGamal is homomorphic with respect to the multiplication whereas
                exponential ElGamal is homomorphic with respect to the addition
            prime_order (boolean): set this to True to pick g of a known prime order q
                while generating keys. Threshold decryption requires this.
        """
        self.exponential = exponential
        self.prime_order = prime_order
        self.keys = keys or self.generate_keys(key_size or 1024)
        self.plaintext_modulo = self.keys["public_key"]["p"]
        self.ciphertext_modulo = self.keys["public_key"]["p"]

    def generate_keys(self, key_size: int):
        """
        Generate public and private keys of ElGamal cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        if self.prime_order is True:
            return self.__generate_prime_order_keys(key_size=key_size)

        # picking a prime modulus p
        p = sympy.randprime(100, 2 ** int(key_size / 2) - 1)

        # picking a generator g
        # g = random.randint(2, int(math.sqrt(p))) # reaches int limit for 3072-bit key
        # g = int(random.uniform(2, float(decimal.Decimal(p).sqrt())))
        g = random.randint(2, int(decimal.Decimal(p).sqrt()))

        # picking a private key x
        x = random.randint(1, p - 2)

        # public key
        y = pow(g, x, p)

        keys["public_key"] = {
            "p": p,
            "g": g,
            "y": y,
        }

        keys["private_key"] = {"x": x}

        return keys

    def __generate_prime_order_keys(self, key_size: int) -> dict:
        """
        Generate keys where p = k * q + 1 for a large prime q, and g has order q.
            Threshold decryption requires the order of g to be known and prime.
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys. public key has q as well.
        """
        bits = max(int(key_size / 2), 8)
        k_bits = max(1, min(16, bits // 4))
        q_bits = bits - k_bits

        # picking a prime modulus p = k * q + 1 for a prime q
        found = False
        while found is False:
            q = sympy.randprime(2 ** (q_bits - 1), 2**q_bits)
            for _ in range(1000):
                k = 2 * random.randint(2 ** (k_bits - 1), 2**k_bits)
                p = k * q + 1
                if p.bit_length() <= bits and sympy.isprime(p):
                    found = True
                    break

        # picking a generator g of the subgroup of prime order q
        while True:
            g = pow(random.randint(2, p - 2), k, p)
            if g != 1:
                break

        # picking a private key x
        x = random.randint(1, q - 1)

        return {
            "public_key": {"p": p, "g": g, "y": pow(g, x, p), "q": q},
            "private_key": {"x": x},
        }

    def generate_random_key(self) -> int:
        """
        ElGamal requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        p = self.keys["public_key"]["p"]
        return random.randint(1, p - 1)

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt plaintext with ElGamal
        Args:
            plaintext (int): message to encrypt
            random_key (int): random key for encryption. Do not set this to a static value.
        Returns
            ciphertext (tuple): c1 and c2
        """
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]
        y = self.keys["public_key"]["y"]
        r = random_key or self.generate_random_key()

        if plaintext > p:
            plaintext = plaintext % p
            logger.debug(
                f"ElGamal can encrypt messages [1, {p}]. "
                f"Seems you exceeded this limit. New plaintext is {plaintext}"
            )

        c1 = pow(g, r, p)
        if self.exponential is False:
            c2 = (plaintext * pow(y, r, p)) % p
        else:
            c2 = (pow(g, plaintext, p) * pow(y, r, p)) % p

        return c1, c2

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt ciphertext with ElGamal
        Args:
            ciphertext (tuple): c1 and c2
        Returns:
            plaintext (int): restored message
        """
        c1, c2 = ciphertext

        x = self.keys["private_key"]["x"]
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]

        m_prime = (c2 * pow(c1, -1 * x, p)) % p

        if self.exponential is False:
            return m_prime

        if self.exponential is True:
            # m_prime = g^m . Find m for known m_prime and known g (DLP).
            m = 0
            while True:
                if pow(g, m, p) == m_prime:
                    return m
                m += 1
                if m > p:
                    raise ValueError(f"Cannot restore the message in [0, {p}]")

        return -1

    def __restore_plaintext(self, m_prime: int) -> int:
        """
        Restore plaintext from m' = c2 / c1^x
        Args:
            m_prime (int): m for ElGamal, g^m for exponential ElGamal
        Returns:
            plaintext (int): restored message
        """
        if self.exponential is False:
            return m_prime

        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]

        # m_prime = g^m . Find m for known m_prime and known g (DLP).
        m = 0
        while True:
            if pow(g, m, p) == m_prime:
                return m
            m += 1
            if m > p:
                raise ValueError(f"Cannot restore the message in [0, {p}]")

    def generate_threshold_keys(self, threshold: int, parties: int) -> List[dict]:
        """
        Split the private key into shares. Any threshold many shareholders can decrypt
            a ciphertext together, but fewer shareholders cannot. Verification keys
            g^share are published to verify partial decryptions.
        Args:
            threshold (int): minimum number of shareholders required to decrypt
            parties (int): total number of shareholders
        Returns:
            keys of shareholders (list of dict): public key and share of each shareholder
        """
        q = self.__get_order()
        if parties >= q:
            raise ValueError(f"Number of parties must be less than the group order {q}")
        shares = threshold_utils.split_secret(
            secret=self.keys["private_key"]["x"],
            threshold=threshold,
            parties=parties,
            modulo=q,
        )
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]
        return threshold_utils.build_share_keys(
            keys=self.keys,
            shares=shares,
            threshold=threshold,
            parties=parties,
            verification_keys=[pow(g, shares[index], p) for index in range(1, parties + 1)],
        )

    def partial_decrypt(self, ciphertext: tuple, prove: bool = False) -> dict:
        """
        Decrypt a ciphertext partially with the share of a shareholder, and optionally
            prove that it is computed with the share behind the verification key
        Args:
            ciphertext (tuple): c1 and c2
            prove (bool): set this to True to attach a zero-knowledge proof of
                correctness. Default is False. Combination with verify=True discards
                partial decryptions without proofs.
        Returns:
            partial decryption (dict): index of the shareholder, c1^share and proof
        """
        threshold_key = threshold_utils.get_threshold_key(self.keys)
        index = threshold_key["index"]
        share = threshold_key["share"]
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]
        c1 = ciphertext[0]
        value = pow(c1, share, p)
        if prove is False:
            return {"index": index, "value": value}
        proof = zkp.prove_dleq(
            group=self.__get_group(),
            g1=g,
            h1=pow(g, share, p),
            g2=c1,
            h2=value,
            x=share,
            domain=PARTIAL_DECRYPTION_DOMAIN,
            context=[p, index],
        )
        return {"index": index, "value": value, "proof": proof}

    def verify_partial_decryption(self, ciphertext: tuple, partial_decryption: dict) -> bool:
        """
        Verify that a partial decryption is computed with the share of its shareholder
        Args:
            ciphertext (tuple): c1 and c2
            partial_decryption (dict): output of partial_decrypt
        Returns:
            is valid (bool)
        """
        verification_keys = self.keys["public_key"].get("verification_keys")
        if verification_keys is None:
            raise ValueError("Public key does not have verification keys of shareholders")
        try:
            index = partial_decryption["index"]
            if not isinstance(index, int) or not 1 <= index <= len(verification_keys):
                return False
            p = self.keys["public_key"]["p"]
            return zkp.verify_dleq(
                group=self.__get_group(),
                g1=self.keys["public_key"]["g"],
                h1=verification_keys[index - 1],
                g2=ciphertext[0],
                h2=partial_decryption["value"],
                proof=partial_decryption["proof"],
                domain=PARTIAL_DECRYPTION_DOMAIN,
                context=[p, index],
            )
        except (KeyError, TypeError, ValueError):
            return False

    def combine_partial_decryptions(
        self, ciphertext: tuple, partial_decryptions: List[dict], verify: bool = False
    ) -> int:
        """
        Restore plaintext from partial decryptions of threshold many shareholders.
            If verify is True, partial decryptions with invalid or missing proofs are discarded.
        Args:
            ciphertext (tuple): c1 and c2
            partial_decryptions (list of dict): partial decryptions of shareholders
            verify (bool): set this to True to check proofs of partial decryptions.
                Default is False, then a wrong partial decryption of a cheating
                shareholder causes a wrong plaintext silently.
        Returns:
            plaintext (int): restored message
        """
        selected = threshold_utils.select_partial_decryptions(
            keys=self.keys,
            partial_decryptions=partial_decryptions,
            verify=(
                (
                    lambda partial_decryption: self.verify_partial_decryption(
                        ciphertext=ciphertext, partial_decryption=partial_decryption
                    )
                )
                if verify is True
                else None
            ),
        )
        p = self.keys["public_key"]["p"]
        q = self.__get_order()
        indices = [partial_decryption["index"] for partial_decryption in selected]

        # c1^x restored in the exponent with lagrange interpolation
        c1_x = 1
        for partial_decryption in selected:
            coefficient = threshold_utils.lagrange_coefficient(
                index=partial_decryption["index"], indices=indices, modulo=q
            )
            c1_x = (c1_x * pow(partial_decryption["value"], coefficient, p)) % p

        m_prime = (ciphertext[1] * pow(c1_x, -1, p)) % p
        return self.__restore_plaintext(m_prime)

    def decrypt_with_proof(self, ciphertext: tuple) -> Tuple[int, dict]:
        """
        Decrypt a ciphertext and prove that decryption is correct without revealing
            the private key. Chaum-Pedersen proof shows that log_g(y) = log_c1(c1^x).
        Args:
            ciphertext (tuple): c1 and c2
        Returns:
            plaintext (int): restored message
            proof (dict): proof of correct decryption
        """
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]
        y = self.keys["public_key"]["y"]
        x = self.keys["private_key"]["x"]
        c1, c2 = ciphertext
        c1_x = pow(c1, x, p)
        proof = zkp.prove_dleq(
            group=self.__get_group(),
            g1=g,
            h1=y,
            g2=c1,
            h2=c1_x,
            x=x,
            domain=DECRYPTION_DOMAIN,
            context=[p, c2],
        )
        return self.__restore_plaintext((c2 * pow(c1_x, -1, p)) % p), proof

    def verify_decryption(self, ciphertext: tuple, plaintext: int, proof: dict) -> bool:
        """
        Verify that a ciphertext is decrypted to the given plaintext with public key only
        Args:
            ciphertext (tuple): c1 and c2
            plaintext (int): claimed plaintext. Exponential ElGamal checks it in modulo q.
            proof (dict): output of decrypt_with_proof
        Returns:
            is valid (bool)
        """
        group = self.__get_group()
        try:
            p = self.keys["public_key"]["p"]
            g = self.keys["public_key"]["g"]
            c1, c2 = ciphertext
            if not isinstance(plaintext, int) or not group.is_member(c1) or not 0 < c2 < p:
                return False

            # c1^x implied by the claimed plaintext
            if self.exponential is True:
                c1_x = (c2 * pow(g, -plaintext, p)) % p
            else:
                if plaintext % p == 0:
                    return False
                c1_x = (c2 * pow(plaintext, -1, p)) % p

            return zkp.verify_dleq(
                group=group,
                g1=g,
                h1=self.keys["public_key"]["y"],
                g2=c1,
                h2=c1_x,
                proof=proof,
                domain=DECRYPTION_DOMAIN,
                context=[p, c2],
            )
        except (TypeError, ValueError):
            return False

    def encrypt_with_proof(
        self, plaintext: int, values: List[int], context: Any = None
    ) -> Tuple[tuple, dict]:
        """
        Encrypt a plaintext and prove that it is one of the given values without
            revealing which one, e.g. a vote is 0 or 1. Disjunctive Chaum-Pedersen proof
            shows that c2 / g^v is y^r for one of the values v.
            Only supported by exponential ElGamal.
        Args:
            plaintext (int): message to encrypt, must be one of values
            values (list of int): allowed values
            context (any): public data bound to the proof, e.g. id of the voter
        Returns:
            ciphertext (tuple): c1 and c2
            proof (dict): proof that ciphertext encrypts one of values
        """
        self.__require_exponential()
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = self.prove_membership(
            ciphertext=ciphertext, plaintext=plaintext, random_key=r, values=values, context=context
        )
        return ciphertext, proof

    def prove_membership(
        self,
        ciphertext: tuple,
        plaintext: int,
        random_key: int,
        values: List[int],
        context: Any = None,
    ) -> dict:
        """
        Prove that a ciphertext encrypts one of the given values, without revealing which
            one. Encryptor of the ciphertext knows its plaintext and random key, e.g. a
            ciphertext restored homomorphically from ciphertexts encrypted by the prover.
        Args:
            ciphertext (tuple): encrypted message
            plaintext (int): message of the ciphertext, must be one of values
            random_key (int): random key of the ciphertext
            values (list of int): allowed values
            context (any): public data bound to the proof
        Returns:
            proof (dict): proof that ciphertext encrypts one of values
        """
        self.__require_exponential()
        return zkp.prove_dleq_or(
            group=self.__get_group(),
            g1=self.keys["public_key"]["g"],
            h1=ciphertext[0],
            g2=self.keys["public_key"]["y"],
            h2s=self.__membership_candidates(ciphertext=ciphertext, values=values),
            x=random_key,
            index=values.index(plaintext),
            domain=MEMBERSHIP_DOMAIN,
            context=[self.keys["public_key"]["p"], ciphertext[1], values, context],
        )

    def combine_random_keys(self, random_keys: List[int]) -> int:
        """
        Random key of the homomorphic sum of ciphertexts, as c1 = g^r multiplies
        Args:
            random_keys (list of int): random keys of ciphertexts
        Returns:
            random key (int): random key of the sum of ciphertexts
        """
        return sum(random_keys)

    def verify_ciphertext(
        self, ciphertext: tuple, proof: dict, values: List[int], context: Any = None
    ) -> bool:
        """
        Verify that a ciphertext encrypts one of the given values with public key only
        Args:
            ciphertext (tuple): c1 and c2
            proof (dict): output of encrypt_with_proof
            values (list of int): allowed values
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        self.__require_exponential()
        group = self.__get_group()
        try:
            return zkp.verify_dleq_or(
                group=group,
                g1=self.keys["public_key"]["g"],
                h1=ciphertext[0],
                g2=self.keys["public_key"]["y"],
                h2s=self.__membership_candidates(ciphertext=ciphertext, values=values),
                proof=proof,
                domain=MEMBERSHIP_DOMAIN,
                context=[self.keys["public_key"]["p"], ciphertext[1], values, context],
            )
        except (TypeError, ValueError):
            return False

    def __membership_candidates(self, ciphertext: tuple, values: List[int]) -> List[int]:
        """
        Candidates c2 / g^v for each value v. Ciphertext encrypts v if and only if
            its candidate is y^r where c1 = g^r.
        Args:
            ciphertext (tuple): c1 and c2
            values (list of int): allowed values
        Returns:
            candidates (list of int)
        """
        p = self.keys["public_key"]["p"]
        g = self.keys["public_key"]["g"]
        return [(ciphertext[1] * pow(g, -value, p)) % p for value in values]

    def __require_exponential(self) -> None:
        """
        Raise an error if this is not exponential ElGamal
        """
        if self.exponential is False:
            raise ValueError(
                "ElGamal does not support proving that a ciphertext encrypts one of given"
                " values. Use Exponential-ElGamal instead."
            )

    def encrypt_with_proof_of_knowledge(
        self, plaintext: int, context: Any = None
    ) -> Tuple[tuple, dict]:
        """
        Encrypt a plaintext and prove knowledge of it without revealing it. Schnorr
            proof shows knowledge of r where c1 = g^r, which reveals the plaintext from c2.
            It is bound to c2, so a copied, re-randomized or modified ciphertext of
            someone else cannot be proven.
        Args:
            plaintext (int): message to encrypt
            context (any): public data bound to the proof, e.g. id of the encryptor
        Returns:
            ciphertext (tuple): c1 and c2
            proof (dict): proof of knowledge
        """
        group = self.__get_group()
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = zkp.prove_dlog(
            group=group,
            g=self.keys["public_key"]["g"],
            h=ciphertext[0],
            x=r,
            domain=self.__knowledge_domain(),
            context=[self.keys["public_key"]["p"], ciphertext[1], context],
        )
        return ciphertext, proof

    def verify_knowledge(self, ciphertext: tuple, proof: dict, context: Any = None) -> bool:
        """
        Verify that the encryptor of a ciphertext knows its plaintext with public key only
        Args:
            ciphertext (tuple): c1 and c2
            proof (dict): output of encrypt_with_proof_of_knowledge
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        group = self.__get_group()
        try:
            p = self.keys["public_key"]["p"]
            c1, c2 = ciphertext
            if not isinstance(c2, int) or not 0 < c2 < p:
                return False
            return zkp.verify_dlog(
                group=group,
                g=self.keys["public_key"]["g"],
                h=c1,
                proof=proof,
                domain=self.__knowledge_domain(),
                context=[p, c2, context],
            )
        except (TypeError, ValueError):
            return False

    def __knowledge_domain(self) -> str:
        """
        Domain of proofs of knowledge, separating ElGamal and exponential ElGamal
        """
        if self.exponential is True:
            return "lightphe/exponential-elgamal/knowledge"
        return "lightphe/elgamal/knowledge"

    def __get_group(self) -> zkp.ModularGroup:
        """
        Get the subgroup of prime order q generated by g
        Returns:
            group (ModularGroup)
        """
        return zkp.ModularGroup(p=self.keys["public_key"]["p"], q=self.__get_order())

    def __get_order(self) -> int:
        """
        Get the prime order q of the generator g
        Returns:
            q (int): order of g
        """
        q = self.keys["public_key"].get("q")
        if q is None:
            raise ValueError(
                "Public key does not have the order q of the generator, which threshold"
                " decryption and zero-knowledge proofs require. Generate new keys with"
                " prime_order=True to use them."
            )
        return q

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic multiplication on encrypted data
        Result of this must be equal to E(m1 * m2)
        Args:
            ciphertext1 (dict): ElGamal ciphertext consisting of c1 and c2 keys
            ciphertext2 (dict): ElGamal ciphertext consisting of c1 and c2 keys
        Returns
            ciphertext (dict): ElGamal ciphertext consisting of c1 and c2 keys
        """
        if self.exponential is True:
            raise ValueError("Exponential ElGamal is not homomorphic with respect to the addition")
        p = self.keys["public_key"]["p"]
        return (ciphertext1[0] * ciphertext2[0]) % p, (ciphertext1[1] * ciphertext2[1]) % p

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (dict): ElGamal ciphertext consisting of c1 and c2 keys
            ciphertext2 (dict): ElGamal ciphertext consisting of c1 and c2 keys
        Returns
            ciphertext (dict): ElGamal ciphertext consisting of c1 and c2 keys
        """
        if self.exponential is False:
            raise ValueError("Regular ElGamal is not homomorphic with respect to the addition")
        p = self.keys["public_key"]["p"]
        return (ciphertext1[0] * ciphertext2[0]) % p, (ciphertext1[1] * ciphertext2[1]) % p

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        if self.exponential is False:
            raise ValueError("ElGamal is not supporting multiplying ciphertext by a known constant")
        p = self.keys["public_key"]["p"]
        if constant > p:
            constant = constant % p
            logger.debug(
                f"ElGamal can encrypt messages [1, {p}]. "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )

        return pow(ciphertext[0], constant, p), pow(ciphertext[1], constant, p)

    def reencrypt(self, ciphertext: tuple) -> tuple:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (int): given ciphertext
        Returns:
            new ciphertext (int): different ciphertext for same plaintext
        """
        if self.exponential is True:
            # then this is additively homomorphic
            neutral_element = 0
        else:
            # then this is multiplicatively homomorphic
            neutral_element = 1

        neutral_encrypted = self.encrypt(plaintext=neutral_element)

        if self.exponential is True:
            reencrypted_value = self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)
        else:
            reencrypted_value = self.multiply(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

        return reencrypted_value
