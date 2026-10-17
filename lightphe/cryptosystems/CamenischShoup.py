# built-in dependencies
import random
import hashlib
from typing import Optional, Union

# 3rd party dependencies
from lightecc import LightECC as ECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.safe_primes import find_safe_prime
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/CamenischShoup.py")

# challenge length of the proof in bits - soundness error is 2^-CHALLENGE_BITS
CHALLENGE_BITS = 128

# statistical zero-knowledge parameter of the proof in bits
STATISTICAL_BITS = 80


class CamenischShoup(Homomorphic):
    """
    Camenisch-Shoup algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    It is designed for verifiable encryption of discrete logarithms. A prover encrypts
    a secret such as the private key of an elliptic curve public key for a trusted
    third party, and proves that the ciphertext really contains it without revealing it.
    Anyone having the public key of the trusted third party can verify the proof,
    and only the trusted third party can decrypt the ciphertext.

    Verifiable encryption has three steps run by three parties:
        - encrypt_verifiably: prover (e.g. Alice) encrypts her secret and creates the proof
        - verify_encryption: verifier (e.g. a bank) checks the proof against the public
            point it already knows, without learning the secret
        - decrypt_verifiable_ciphertext: trusted third party restores the secret
    Only the last step requires the private key.

    Ciphertexts for homomorphic operations are (u, e) pairs. Verifiable ciphertexts
    additionally have a validity tag v bound to a label, which makes them secure against
    chosen ciphertext attacks. Homomorphic operations drop that tag, as non-malleability
    and homomorphism contradict each other.

    The proof follows the paper with Fiat-Shamir heuristic. Its soundness relies on
    the auxiliary RSA modulus n_bar, whose factorization is discarded during key
    generation and must not be known by the prover.
    Ref: Camenisch, J., Shoup, V. (2003). Practical Verifiable Encryption and Decryption
        of Discrete Logarithms. CRYPTO 2003.
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "g", "y1", "y2", "y3", "n_bar", "g_bar", "h_bar"],
        "private_key": ["x1", "x2", "x3"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        max_tries: int = 10000,
        form: Optional[str] = None,
        curve: Optional[str] = None,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
            max_tries (int): maximum attempts to generate keys
            form (str): form of the elliptic curve of the secrets to be encrypted verifiably.
                Options: 'weierstrass' (default), 'edwards', 'koblitz'.
            curve (str): elliptic curve of the secrets to be encrypted verifiably.
                Default is secp256k1 for weierstrass form.
        """
        self.form = form
        self.curve = curve
        self.__ecc: Optional[ECC] = None

        self.keys = keys or self.generate_keys(
            key_size=key_size or 1024, max_tries=max_tries
        )
        n = self.keys["public_key"]["n"]
        self.plaintext_modulo = n
        self.ciphertext_modulo = n * n

    @property
    def ecc(self) -> ECC:
        """
        Elliptic curve of the secrets to be encrypted verifiably. Built lazily as
            homomorphic operations do not need it.
        """
        if self.__ecc is None:
            self.__ecc = ECC(form_name=self.form, curve_name=self.curve)
        return self.__ecc

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Camenisch-Shoup cryptosystem
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
            raise ValueError(f"Key size {key_size} is too small for Camenisch-Shoup")

        # n = pq where p = 2p' + 1 and q = 2q' + 1 are safe primes
        p, q = self.__find_safe_prime_pair(key_size=key_size, max_tries=max_tries)
        n = p * q
        n_square = n * n
        p_prime = (p - 1) // 2
        q_prime = (q - 1) // 2

        # g is a 2n-th power in Z_{n^2}*, so its order divides p'q'
        for _ in range(max_tries):
            g = pow(random.randint(2, n_square - 1), 2 * n, n_square)
            if pow(g, p_prime, n_square) != 1 and pow(g, q_prime, n_square) != 1:
                break
        else:
            raise ValueError(f"Failed to find a suitable generator in {max_tries} tries")

        x1, x2, x3 = [random.randint(1, n_square // 4) for _ in range(3)]

        # auxiliary RSA modulus for the proof. its factorization is discarded.
        p_bar, q_bar = self.__find_safe_prime_pair(key_size=key_size, max_tries=max_tries)
        n_bar = p_bar * q_bar
        for _ in range(max_tries):
            h_bar = pow(random.randint(2, n_bar - 1), 2, n_bar)
            if h_bar % p_bar != 1 and h_bar % q_bar != 1:
                break
        else:
            raise ValueError(f"Failed to find a suitable generator in {max_tries} tries")
        g_bar = pow(h_bar, random.randint(2, n_bar // 4), n_bar)

        keys["public_key"]["n"] = n
        keys["public_key"]["g"] = g
        keys["public_key"]["y1"] = pow(g, x1, n_square)
        keys["public_key"]["y2"] = pow(g, x2, n_square)
        keys["public_key"]["y3"] = pow(g, x3, n_square)
        keys["public_key"]["n_bar"] = n_bar
        keys["public_key"]["g_bar"] = g_bar
        keys["public_key"]["h_bar"] = h_bar

        keys["private_key"]["x1"] = x1
        keys["private_key"]["x2"] = x2
        keys["private_key"]["x3"] = x3

        return keys

    def generate_random_key(self) -> int:
        """
        Camenisch-Shoup requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        return random.randint(1, max(1, n // 4))

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Camenisch-Shoup
        Args:
            plaintext (int): message to encrypt in [0, n)
            random_key (int): Camenisch-Shoup requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): u = g^r mod n^2 and e = y1^r (1 + n)^m mod n^2
        """
        n = self.keys["public_key"]["n"]
        g = self.keys["public_key"]["g"]
        y1 = self.keys["public_key"]["y1"]
        n_square = n * n
        r = random_key or self.generate_random_key()

        if plaintext >= n:
            plaintext = plaintext % n
            logger.debug(
                f"Camenisch-Shoup can encrypt messages [0, {n}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        u = pow(g, r, n_square)
        e = (pow(y1, r, n_square) * (1 + plaintext * n)) % n_square
        return u, e

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Camenisch-Shoup
        Args:
            ciphertext (tuple): encrypted message as (u, e) pair
        Returns:
            plaintext (int): restored message
        """
        if len(ciphertext) != 2:
            raise ValueError(
                "Ciphertext must be a (u, e) pair. "
                "Decrypt verifiable ciphertexts with their labels."
            )
        u, e = ciphertext
        return self.__recover(u=u, e=e)

    def encrypt_with_label(
        self, plaintext: int, label: str, random_key: Optional[int] = None
    ) -> tuple:
        """
        Encrypt a given plaintext with Camenisch-Shoup secure against chosen ciphertext
            attacks. The ciphertext can be decrypted with the same label only.
        Args:
            plaintext (int): message to encrypt in [0, n)
            label (str): public data bound to the ciphertext, e.g. decryption conditions
            random_key (int): one time random key for encryption
        Returns:
            ciphertext (tuple): (u, e, v) where v is the validity tag
        """
        n = self.keys["public_key"]["n"]
        n_square = n * n
        r = random_key or self.generate_random_key()

        u, e = self.encrypt(plaintext=plaintext, random_key=r)
        tag_base = self.__tag_base(u=u, e=e, label=label)
        v = self.__abs(pow(tag_base, r, n_square))
        return u, e, v

    def decrypt_with_label(self, ciphertext: tuple, label: str) -> int:
        """
        Decrypt a ciphertext created with encrypt_with_label. It is rejected
            if it was modified or its label is different.
        Args:
            ciphertext (tuple): (u, e, v) triple
            label (str): label used in encryption
        Returns:
            plaintext (int): restored message
        """
        n = self.keys["public_key"]["n"]
        x2 = self.keys["private_key"]["x2"]
        x3 = self.keys["private_key"]["x3"]
        n_square = n * n

        if not isinstance(ciphertext, (tuple, list)) or len(ciphertext) != 3:
            raise ValueError("Verifiable ciphertext must be a (u, e, v) triple")
        u, e, v = ciphertext

        tag_exponent = 2 * (x2 + self.__hash_tag(u=u, e=e, label=label) * x3)
        if v != self.__abs(v) or pow(u, tag_exponent, n_square) != pow(v, 2, n_square):
            raise ValueError("Ciphertext is invalid or was encrypted with a different label")

        return self.__recover(u=u, e=e)

    def encrypt_verifiably(self, secret: int, label: str = "") -> dict:
        """
        Encrypt the discrete logarithm of an elliptic curve point, e.g. a private key,
            for the owner of this cryptosystem and prove that the ciphertext contains it.
            Runs on prover side, e.g. Alice escrowing her wallet key to a trusted third
            party. Only the prover can call this, because it needs the secret itself.
            Public key of the trusted third party is enough, the private key is not needed.
            Output is sent to the verifier, who checks it with verify_encryption.
        Args:
            secret (int): discrete logarithm of the public point, i.e. public point = G * secret
            label (str): public data bound to the ciphertext, e.g. decryption conditions
        Returns:
            verifiable ciphertext (dict): ciphertext, commitment and proof
        """
        self.__validate_verifiable_encryption()
        pk = self.keys["public_key"]
        n, g, y1 = pk["n"], pk["g"], pk["y1"]
        n_bar, g_bar, h_bar = pk["n_bar"], pk["g_bar"], pk["h_bar"]
        n_square = n * n
        order = self.ecc.n
        bound = 1 << (CHALLENGE_BITS + STATISTICAL_BITS)

        m = secret % order
        if m == 0:
            raise ValueError("Secret must not be a multiple of the order of the curve")
        public_point = self.ecc.G * m

        r = self.generate_random_key()
        u, e, v = self.encrypt_with_label(plaintext=m, label=label, random_key=r)
        tag_base = self.__tag_base(u=u, e=e, label=label)

        # commitment to the secret in auxiliary group
        s = random.randint(1, n_bar // 4)
        l = (pow(g_bar, m, n_bar) * pow(h_bar, s, n_bar)) % n_bar

        # random masks statistically hiding the secret, r and s
        r_mask = random.randint(-(n // 4) * bound, (n // 4) * bound)
        s_mask = random.randint(-(n_bar // 4) * bound, (n_bar // 4) * bound)
        m_mask = random.randint(-order * bound, order * bound)

        commitments = (
            pow(g, 2 * r_mask, n_square),
            (pow(y1, 2 * r_mask, n_square) * pow(1 + n, 2 * m_mask, n_square)) % n_square,
            pow(tag_base, 2 * r_mask, n_square),
            self.ecc.G * (m_mask % order),
            (pow(g_bar, m_mask, n_bar) * pow(h_bar, s_mask, n_bar)) % n_bar,
        )

        challenge = self.__challenge(
            public_point=public_point,
            label=label,
            ciphertext=(u, e, v),
            l=l,
            commitments=commitments,
        )

        return {
            "ciphertext": (u, e, v),
            "commitment": l,
            "proof": {
                "challenge": challenge,
                "r": r_mask - challenge * r,
                "s": s_mask - challenge * s,
                "m": m_mask - challenge * m,
            },
        }

    def verify_encryption(
        self,
        verifiable_ciphertext: dict,
        public_point: Union[tuple, EllipticCurvePoint],
        label: str = "",
    ) -> bool:
        """
        Verify that a verifiable ciphertext contains the discrete logarithm of a public
            point without decrypting it. Runs on verifier side, e.g. a bank that knows
            Alice's public key only. The verifier cannot trust the prover's word, because
            the prover could encrypt 0 or an unrelated key instead. This checks the proof
            against the public point and the label that the verifier already knows, so it
            confirms the escrow is real without learning the secret. Public key of the
            trusted third party is enough, the private key is not needed.
        Args:
            verifiable_ciphertext (dict): created by encrypt_verifiably
            public_point (tuple or EllipticCurvePoint): public point known by the verifier
            label (str): label that the ciphertext is expected to be bound to
        Returns:
            is valid (bool): True if the ciphertext contains the secret of the public point
        """
        self.__validate_verifiable_encryption()
        pk = self.keys["public_key"]
        n, g, y1 = pk["n"], pk["g"], pk["y1"]
        n_bar, g_bar, h_bar = pk["n_bar"], pk["g_bar"], pk["h_bar"]
        n_square = n * n
        order = self.ecc.n

        parsed = self.__parse_verifiable_ciphertext(verifiable_ciphertext)
        if parsed is None:
            return False
        u, e, v, l, challenge, r_z, s_z, m_z = parsed

        if not isinstance(public_point, EllipticCurvePoint):
            x, y = public_point
            public_point = EllipticCurvePoint(x=x, y=y, curve=self.ecc.curve)
        if public_point.get_point() == self.ecc.O.get_point():
            return False
        tag_base = self.__tag_base(u=u, e=e, label=label)

        try:
            commitments = (
                (pow(u, 2 * challenge, n_square) * pow(g, 2 * r_z, n_square)) % n_square,
                (
                    pow(e, 2 * challenge, n_square)
                    * pow(y1, 2 * r_z, n_square)
                    * pow(1 + n, 2 * m_z, n_square)
                )
                % n_square,
                (pow(v, 2 * challenge, n_square) * pow(tag_base, 2 * r_z, n_square))
                % n_square,
                public_point * challenge + self.ecc.G * (m_z % order),
                (pow(l, challenge, n_bar) * pow(g_bar, m_z, n_bar) * pow(h_bar, s_z, n_bar))
                % n_bar,
            )
        except (ValueError, TypeError):
            # not invertible or point at infinity
            return False

        return challenge == self.__challenge(
            public_point=public_point,
            label=label,
            ciphertext=(u, e, v),
            l=l,
            commitments=commitments,
        )

    def __parse_verifiable_ciphertext(self, verifiable_ciphertext: dict) -> Optional[tuple]:
        """
        Extract the ciphertext, commitment and proof, and check their types and ranges
        Args:
            verifiable_ciphertext (dict): created by encrypt_verifiably
        Returns:
            values (tuple): u, e, v, l, challenge, r, s and m of the proof,
                or None if the verifiable ciphertext is malformed
        """
        n = self.keys["public_key"]["n"]
        n_bar = self.keys["public_key"]["n_bar"]
        bound = 1 << (CHALLENGE_BITS + STATISTICAL_BITS)

        try:
            u, e, v = verifiable_ciphertext["ciphertext"]
            proof = verifiable_ciphertext["proof"]
            values = (
                u,
                e,
                v,
                verifiable_ciphertext["commitment"],
                proof["challenge"],
                proof["r"],
                proof["s"],
                proof["m"],
            )
        except (KeyError, TypeError, ValueError):
            return None

        l, challenge, m_z = values[3], values[4], values[7]
        is_valid = (
            all(isinstance(x, int) for x in values)
            and all(0 < x < n * n for x in [u, e, v])
            and v == self.__abs(v)
            and 0 < l < n_bar
            and 0 <= challenge < (1 << CHALLENGE_BITS)
            # secret must be small enough to be restored from its encryption mod n
            and abs(m_z) <= 2 * self.ecc.n * bound
        )
        return values if is_valid else None

    def decrypt_verifiable_ciphertext(self, verifiable_ciphertext: dict, label: str = "") -> int:
        """
        Restore the secret from a verifiable ciphertext. Runs on the side of the private
            key owner, e.g. a trusted third party, when the conditions in the label are met.
            This is the only step requiring the private key, and the only way to restore
            the secret. It does not check the proof, as verify_encryption does that.
        Args:
            verifiable_ciphertext (dict): created by encrypt_verifiably
            label (str): label used in encryption
        Returns:
            secret (int): discrete logarithm of the public point
        """
        n = self.keys["public_key"]["n"]
        m = self.decrypt_with_label(
            ciphertext=verifiable_ciphertext["ciphertext"], label=label
        )
        # proof guarantees that the secret is in (-n/2, n/2)
        if m > n // 2:
            m -= n
        return m % self.ecc.n

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Validity tags of verifiable ciphertexts are dropped.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Camenisch-Shoup
            ciphertext2 (tuple): 2nd ciphertext created with Camenisch-Shoup
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Camenisch-Shoup
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
        Validity tags of verifiable ciphertexts are dropped.
        Args:
            ciphertext (tuple): ciphertext created with Camenisch-Shoup
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Camenisch-Shoup
        """
        n = self.keys["public_key"]["n"]
        n_square = n * n

        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Camenisch-Shoup can encrypt messages [0, {n}). "
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

    def __recover(self, u: int, e: int) -> int:
        """
        Restore plaintext from (u, e) pair
        Args:
            u (int): g^r mod n^2
            e (int): y1^r (1 + n)^m mod n^2
        Returns:
            plaintext (int): m
        """
        n = self.keys["public_key"]["n"]
        x1 = self.keys["private_key"]["x1"]
        n_square = n * n

        # (e / u^x1)^(2t) = (1 + n)^m where t = 1/2 mod n
        two_t = 2 * pow(2, -1, n)
        m_hat = pow((e * pow(pow(u, x1, n_square), -1, n_square)) % n_square, two_t, n_square)
        if m_hat % n != 1:
            raise ValueError("Ciphertext is invalid")
        return (m_hat - 1) // n

    def __tag_base(self, u: int, e: int, label: str) -> int:
        """
        Base of the validity tag v
        Args:
            u (int): first component of the ciphertext
            e (int): second component of the ciphertext
            label (str): label bound to the ciphertext
        Returns:
            y2 * y3^H(u, e, label) mod n^2
        """
        n = self.keys["public_key"]["n"]
        y2 = self.keys["public_key"]["y2"]
        y3 = self.keys["public_key"]["y3"]
        n_square = n * n
        return (y2 * pow(y3, self.__hash_tag(u=u, e=e, label=label), n_square)) % n_square

    def __hash_tag(self, u: int, e: int, label: str) -> int:
        """
        Hash of a ciphertext and its label for the validity tag. It is smaller than
            p' and q' as required by the scheme.
        """
        n = self.keys["public_key"]["n"]
        bits = min(256, max(1, n.bit_length() // 2 - 2))
        digest = hashlib.sha256(f"tag|{u}|{e}|{label}".encode("utf-8")).digest()
        return int.from_bytes(digest, "big") % (1 << bits)

    def __challenge(
        self,
        public_point: EllipticCurvePoint,
        label: str,
        ciphertext: tuple,
        l: int,
        commitments: tuple,
    ) -> int:
        """
        Fiat-Shamir challenge of the proof
        """
        pk = self.keys["public_key"]
        items = [pk[key] for key in self.REQUIRED_KEYS["public_key"]]
        items += [self.ecc.G.get_point(), public_point.get_point(), label]
        items += list(ciphertext) + [l]
        items += [c.get_point() if isinstance(c, EllipticCurvePoint) else c for c in commitments]
        data = "|".join(str(item) for item in items)
        digest = hashlib.sha256(f"challenge|{data}".encode("utf-8")).digest()
        return int.from_bytes(digest, "big") % (1 << CHALLENGE_BITS)

    def __abs(self, a: int) -> int:
        """
        Absolute value of an element of Z_{n^2}, where elements greater than n^2 / 2
            are considered negative
        """
        n = self.keys["public_key"]["n"]
        n_square = n * n
        return n_square - a if a > n_square // 2 else a

    def __validate_verifiable_encryption(self) -> None:
        """
        Secrets must be restorable from their encryption mod n, even if they are
            extracted from a cheating prover
        """
        n = self.keys["public_key"]["n"]
        minimum = self.ecc.n << (CHALLENGE_BITS + STATISTICAL_BITS + 3)
        if n <= minimum:
            raise ValueError(
                f"Key size {n.bit_length()} is too small for verifiable encryption. "
                f"It must be greater than {minimum.bit_length()} bits for this curve."
            )

    @staticmethod
    def __find_safe_prime_pair(key_size: int, max_tries: int) -> tuple:
        """
        Find two different safe primes for a modulus of key_size bits
        """
        p = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
        q = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
        while q == p:
            q = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
        return p, q
