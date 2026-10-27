import random
import math
from typing import Any, Optional, List, Tuple
import sympy
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger
from lightphe.commons import threshold as threshold_utils
from lightphe.commons import zkp

logger = Logger(module="lightphe/cryptosystems/DamgardJurik.py")

MEMBERSHIP_DOMAIN = "lightphe/damgard-jurik/membership"
KNOWLEDGE_DOMAIN = "lightphe/damgard-jurik/knowledge"
PARTIAL_DECRYPTION_DOMAIN = "lightphe/damgard-jurik/partial-decryption"


class DamgardJurik(Homomorphic):
    """
    Damgard-Jurik algorithm is a generalization of Paillier.
    It is homomorphic with respect to the addition.
    Ref: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/
    """

    REQUIRED_KEYS = {
        "public_key": ["g", "n", "s"],
        "private_key": ["phi"],
    }

    def __init__(self, s: int = 2, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            s (int): cryptosystem's module is going to be n^(s+1). if s == 1 then this is Paillier
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
        """
        self.keys = keys or self.generate_keys(key_size=key_size or 1024, s=s)
        n = self.keys["public_key"]["n"]
        self.plaintext_modulo = n
        self.ciphertext_modulo = pow(n, s + 1)

    def generate_keys(self, key_size: int, s: Optional[int] = None):
        """
        Generate public and private keys of Paillier cryptosystem
        Args:
            s (int): cryptosystem's module is going to be n^(s+1). if s == 1 then this is Paillier
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        # picking a prime modulus p
        p = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

        # picking a prime modulus q
        q = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

        n = p * q
        phi = (p - 1) * (q - 1)
        g = 1 + n

        keys["private_key"]["phi"] = phi
        keys["public_key"]["g"] = g
        keys["public_key"]["n"] = n
        keys["public_key"]["s"] = s

        return keys

    def generate_random_key(self) -> int:
        """
        Paillier requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            r = random.randint(0, n)
            if math.gcd(r, n) == 1:
                break
        return r

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with Paillier
        Args:
            plaintext (int): message to encrypt
            random_key (int): Paillier requires a random key that co-prime to n.
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        g = self.keys["public_key"]["g"]
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        r = random_key or self.generate_random_key()
        modulo = pow(n, s + 1)

        # assert math.gcd(r, n) == 1
        c = (pow(g, plaintext, modulo) * pow(r, n, modulo)) % modulo
        # c = (pow(g, plaintext, modulo) * pow(r, pow(n, s), modulo)) % modulo
        if math.gcd(c, modulo) != 1:
            logger.info(f"WARNING! gcd({c=}, {modulo=}) != 1")
        return c

    def decrypt(self, ciphertext: int):
        """
        Decrypt a given ciphertext with Paillier
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        phi = self.keys["private_key"]["phi"]
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        mu = pow(phi, -1, n)
        modulo = pow(n, s + 1)
        return (self.lx(pow(ciphertext, phi, modulo)) * mu) % (n)

    def generate_threshold_keys(self, threshold: int, parties: int) -> List[dict]:
        """
        Split the private key into shares. Any threshold many shareholders can decrypt
            a ciphertext together, but fewer shareholders cannot. If keys are generated
            with safe primes, verification keys are published to verify partial decryptions.
        Args:
            threshold (int): minimum number of shareholders required to decrypt
            parties (int): total number of shareholders
        Returns:
            keys of shareholders (list of dict): public key and share of each shareholder
        """
        return threshold_utils.generate_paillier_threshold_keys(
            keys=self.keys,
            s=self.keys["public_key"]["s"],
            modulo=self.ciphertext_modulo,
            threshold=threshold,
            parties=parties,
        )

    def partial_decrypt(self, ciphertext: int, prove: bool = False) -> dict:
        """
        Decrypt a ciphertext partially with the share of a shareholder, and optionally
            prove that it is computed with the share behind the verification key
        Args:
            ciphertext (int): encrypted message
            prove (bool): set this to True to attach a zero-knowledge proof of
                correctness. Default is False. Keys must be generated with safe primes.
        Returns:
            partial decryption (dict): index of the shareholder, value and optional proof
        """
        return threshold_utils.paillier_partial_decrypt(
            keys=self.keys,
            ciphertext=ciphertext,
            modulo=self.ciphertext_modulo,
            prove=prove,
            domain=PARTIAL_DECRYPTION_DOMAIN,
        )

    def verify_partial_decryption(self, ciphertext: int, partial_decryption: dict) -> bool:
        """
        Verify that a partial decryption is computed with the share of its shareholder
        Args:
            ciphertext (int): encrypted message
            partial_decryption (dict): output of partial_decrypt with prove=True
        Returns:
            is valid (bool)
        """
        return threshold_utils.verify_paillier_partial_decryption(
            keys=self.keys,
            ciphertext=ciphertext,
            partial_decryption=partial_decryption,
            modulo=self.ciphertext_modulo,
            domain=PARTIAL_DECRYPTION_DOMAIN,
        )

    def combine_partial_decryptions(
        self, ciphertext: int, partial_decryptions: List[dict], verify: bool = False
    ) -> int:
        """
        Restore plaintext from partial decryptions of threshold many shareholders.
            If verify is True, partial decryptions with invalid or missing proofs are discarded.
        Args:
            ciphertext (int): encrypted message
            partial_decryptions (list of dict): partial decryptions of shareholders
            verify (bool): set this to True to check proofs of partial decryptions.
                Default is False, then a wrong partial decryption of a cheating
                shareholder causes a wrong plaintext silently. Keys must be generated
                with safe primes.
        Returns:
            plaintext (int): restored message
        """
        return threshold_utils.combine_paillier_partial_decryptions(
            keys=self.keys,
            ciphertext=ciphertext,
            partial_decryptions=partial_decryptions,
            modulo=self.ciphertext_modulo,
            verify=verify,
            domain=PARTIAL_DECRYPTION_DOMAIN,
        )

    def decrypt_with_proof(self, ciphertext: int) -> Tuple[int, dict]:
        """
        Decrypt a ciphertext and prove that decryption is correct. Randomness of the
            ciphertext is the proof, and anyone having public key can check it.
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
            proof (dict): randomness of the ciphertext
        """
        plaintext = self.decrypt(ciphertext)
        proof = zkp.prove_paillier_decryption(
            ciphertext=ciphertext,
            plaintext=plaintext,
            n=self.keys["public_key"]["n"],
            phi=self.keys["private_key"]["phi"],
        )
        return plaintext, proof

    def verify_decryption(self, ciphertext: int, plaintext: int, proof: dict) -> bool:
        """
        Verify that a ciphertext is decrypted to the given plaintext with public key only
        Args:
            ciphertext (int): encrypted message
            plaintext (int): claimed plaintext
            proof (dict): output of decrypt_with_proof
        Returns:
            is valid (bool)
        """
        return zkp.verify_paillier_decryption(
            ciphertext=ciphertext,
            plaintext=plaintext,
            proof=proof,
            n=self.keys["public_key"]["n"],
        )

    def encrypt_with_proof(
        self, plaintext: int, values: List[int], context: Any = None
    ) -> Tuple[int, dict]:
        """
        Encrypt a plaintext and prove that it is one of the given values without
            revealing which one, e.g. a vote is 0 or 1. 1-out-of-k proof of Damgard and
            Jurik shows that c * g^-v is an n-th power for one of the values v.
        Args:
            plaintext (int): message to encrypt, must be one of values
            values (list of int): allowed values
            context (any): public data bound to the proof, e.g. id of the voter
        Returns:
            ciphertext (int): encrypted message
            proof (dict): proof that ciphertext encrypts one of values
        """
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = self.prove_membership(
            ciphertext=ciphertext, plaintext=plaintext, random_key=r, values=values, context=context
        )
        return ciphertext, proof

    def prove_membership(
        self,
        ciphertext: int,
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
            ciphertext (int): encrypted message
            plaintext (int): message of the ciphertext, must be one of values
            random_key (int): random key of the ciphertext
            values (list of int): allowed values
            context (any): public data bound to the proof
        Returns:
            proof (dict): proof that ciphertext encrypts one of values
        """
        n = self.keys["public_key"]["n"]
        modulo = pow(n, self.keys["public_key"]["s"] + 1)
        return zkp.prove_nth_power_or(
            n=n,
            modulo=modulo,
            us=zkp.paillier_membership_candidates(
                ciphertext=ciphertext, values=values, n=n, modulo=modulo
            ),
            r=random_key,
            index=values.index(plaintext),
            domain=MEMBERSHIP_DOMAIN,
            context=[values, context],
        )

    def combine_random_keys(self, random_keys: List[int]) -> int:
        """
        Random key of the homomorphic sum of ciphertexts, as r^n multiplies
        Args:
            random_keys (list of int): random keys of ciphertexts
        Returns:
            random key (int): random key of the sum of ciphertexts
        """
        n = self.keys["public_key"]["n"]
        modulo = pow(n, self.keys["public_key"]["s"] + 1)
        combined = 1
        for random_key in random_keys:
            combined = (combined * random_key) % modulo
        return combined

    def verify_ciphertext(
        self, ciphertext: int, proof: dict, values: List[int], context: Any = None
    ) -> bool:
        """
        Verify that a ciphertext encrypts one of the given values with public key only
        Args:
            ciphertext (int): encrypted message
            proof (dict): output of encrypt_with_proof
            values (list of int): allowed values
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        if not isinstance(ciphertext, int):
            return False
        n = self.keys["public_key"]["n"]
        modulo = pow(n, self.keys["public_key"]["s"] + 1)
        if not 0 < ciphertext < modulo or math.gcd(ciphertext, n) != 1:
            return False
        return zkp.verify_nth_power_or(
            n=n,
            modulo=modulo,
            us=zkp.paillier_membership_candidates(
                ciphertext=ciphertext, values=values, n=n, modulo=modulo
            ),
            proof=proof,
            domain=MEMBERSHIP_DOMAIN,
            context=[values, context],
        )

    def encrypt_with_proof_of_knowledge(
        self, plaintext: int, context: Any = None
    ) -> Tuple[int, dict]:
        """
        Encrypt a plaintext and prove knowledge of the plaintext and randomness
            without revealing them. So, a copied, re-randomized or modified ciphertext
            of someone else cannot be proven.
        Args:
            plaintext (int): message to encrypt
            context (any): public data bound to the proof, e.g. id of the encryptor
        Returns:
            ciphertext (int): encrypted message
            proof (dict): proof of knowledge
        """
        n = self.keys["public_key"]["n"]
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = zkp.prove_paillier_knowledge(
            ciphertext=ciphertext,
            plaintext=plaintext,
            r=r,
            n=n,
            modulo=pow(n, self.keys["public_key"]["s"] + 1),
            domain=KNOWLEDGE_DOMAIN,
            context=context,
        )
        return ciphertext, proof

    def verify_knowledge(self, ciphertext: int, proof: dict, context: Any = None) -> bool:
        """
        Verify that the encryptor of a ciphertext knows its plaintext with public key only
        Args:
            ciphertext (int): encrypted message
            proof (dict): output of encrypt_with_proof_of_knowledge
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        n = self.keys["public_key"]["n"]
        return zkp.verify_paillier_knowledge(
            ciphertext=ciphertext,
            proof=proof,
            n=n,
            modulo=pow(n, self.keys["public_key"]["s"] + 1),
            domain=KNOWLEDGE_DOMAIN,
            context=context,
        )

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Encryption calculations are done in module n squared.
        Args:
            ciphertext1 (int): 1st ciphertext created with Paillier
            ciphertext2 (int): 2nd ciphertext created with Paillier
        Returns:
            ciphertext3 (int): 3rd ciphertext created with Paillier
        """
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        modulo = pow(n, s + 1)
        return (ciphertext1 * ciphertext2) % modulo

    def multiply_by_constant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext by a known plain constant
        Result of this must be equal to E(m1 * m2), where E(m1) = ciphertext
        Encryption calculations are done in module n squared.
        Args:
            ciphertext (int): ciphertext created with Damgard-Jurik
            constant (int): a known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Damgard-Jurik
        """
        n = self.keys["public_key"]["n"]
        if constant > self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Damgard-Jurik can encrypt messages [1, {n}]. "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )
        return pow(ciphertext, constant, self.ciphertext_modulo)

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

    def lx(self, x: int) -> int:
        """
        Find logarithm over cyclic group
        Args:
            x (int): some integer
        Returns:
            lx (int): (x-1) / n
        """
        n = self.keys["public_key"]["n"]
        y = (x - 1) // n
        assert y - int(y) == 0
        return int(y)
