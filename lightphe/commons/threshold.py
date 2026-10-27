# built-in dependencies
import copy
import math
import random
from typing import Callable, Dict, List, Optional

# 3rd party dependencies
import sympy

# project dependencies
from lightphe.commons.logger import Logger
from lightphe.commons.safe_primes import find_safe_prime
from lightphe.commons import zkp

logger = Logger(module="lightphe/commons/threshold.py")

SAFE_PRIMES_REQUIRED_MSG = (
    "Partial decryptions of Paillier and Damgard-Jurik can be proven only if keys are"
    " generated with safe_primes=True"
)

# Threshold decryption splits a private key into shares with Shamir's secret sharing.
# Any `threshold` of `parties` shareholders decrypt a ciphertext together,
# whereas fewer shareholders learn nothing about the plaintext.
# Ref: Shamir, "How to share a secret", 1979
# Ref: Shoup, "Practical threshold signatures", 2000
# Ref: Damgard & Jurik, "A generalisation, a simplification and some applications
#   of Paillier's probabilistic public-key system", 2001


def validate_threshold(threshold: int, parties: int) -> None:
    """
    Check that a threshold scheme is well defined
    Args:
        threshold (int): minimum number of shareholders required to decrypt
        parties (int): total number of shareholders
    """
    if not isinstance(threshold, int) or not isinstance(parties, int):
        raise ValueError("threshold and parties must be integers")
    if threshold < 1:
        raise ValueError(f"threshold must be at least 1, got {threshold}")
    if parties < threshold:
        raise ValueError(
            f"parties ({parties}) must be greater than or equal to threshold ({threshold})"
        )


def split_secret(secret: int, threshold: int, parties: int, modulo: int) -> Dict[int, int]:
    """
    Split a secret into shares with a random polynomial f of degree threshold - 1
        where f(0) = secret. Share of the party with index i is f(i) mod modulo.
    Args:
        secret (int): secret to share
        threshold (int): minimum number of shares required to restore the secret
        parties (int): number of shares
        modulo (int): shares are reduced in this modulo
    Returns:
        shares (dict): party index (1, ..., parties) to its share
    """
    validate_threshold(threshold=threshold, parties=parties)
    coefficients = [secret % modulo] + [
        random.randint(0, modulo - 1) for _ in range(threshold - 1)
    ]

    shares = {}
    for index in range(1, parties + 1):
        # horner's method
        share = 0
        for coefficient in reversed(coefficients):
            share = (share * index + coefficient) % modulo
        shares[index] = share
    return shares


def lagrange_coefficient(index: int, indices: List[int], modulo: int) -> int:
    """
    Lagrange coefficient of a party at 0 in a modulo where differences of indices
        are invertible, e.g. a prime order of a group
    Args:
        index (int): index of the party
        indices (list of int): indices of all parties joining decryption
        modulo (int): modulo of the coefficient
    Returns:
        coefficient (int): Π j / (j - index) mod modulo over other indices j
    """
    numerator = 1
    denominator = 1
    for j in indices:
        if j == index:
            continue
        numerator = (numerator * j) % modulo
        denominator = (denominator * (j - index)) % modulo
    return (numerator * pow(denominator, -1, modulo)) % modulo


def scaled_lagrange_coefficient(index: int, indices: List[int], delta: int) -> int:
    """
    Lagrange coefficient of a party at 0 multiplied by delta = parties!
        This is always an integer, so it works in groups of unknown order.
    Args:
        index (int): index of the party
        indices (list of int): indices of all parties joining decryption
        delta (int): factorial of the number of parties
    Returns:
        coefficient (int): delta * Π j / (j - index) over other indices j
    """
    numerator = delta
    denominator = 1
    for j in indices:
        if j == index:
            continue
        numerator *= j
        denominator *= j - index
    assert numerator % denominator == 0
    return numerator // denominator


def build_share_keys(
    keys: dict,
    shares: Dict[int, int],
    threshold: int,
    parties: int,
    verification_keys: Optional[list] = None,
) -> List[dict]:
    """
    Add threshold parameters into public key, and create key of each shareholder
        consisting of public key and its own share. Keys of shareholders do not
        have private key.
    Args:
        keys (dict): private - public key pair of the dealer. It is updated in place.
        shares (dict): party index to its share
        threshold (int): minimum number of shareholders required to decrypt
        parties (int): total number of shareholders
        verification_keys (list): public commitments to shares, e.g. g^share, to verify
            partial decryptions. Item k belongs to the party with index k + 1.
    Returns:
        keys of shareholders (list of dict)
    """
    keys["public_key"]["threshold"] = threshold
    keys["public_key"]["parties"] = parties
    if verification_keys is not None:
        keys["public_key"]["verification_keys"] = verification_keys

    public_keys = {key: value for key, value in keys.items() if key != "private_key"}

    share_keys = []
    for index, share in shares.items():
        share_key = copy.deepcopy(public_keys)
        share_key["threshold_key"] = {"index": index, "share": share}
        share_keys.append(share_key)
    return share_keys


def get_threshold_key(keys: dict) -> dict:
    """
    Get the threshold key of a shareholder
    Args:
        keys (dict): keys of the shareholder
    Returns:
        threshold key (dict): index and share of the shareholder
    """
    threshold_key = keys.get("threshold_key")
    if threshold_key is None:
        raise ValueError("You must have threshold key to perform partial decryption")
    return threshold_key


def select_partial_decryptions(
    keys: dict,
    partial_decryptions: List[dict],
    verify: Optional[Callable[[dict], bool]] = None,
) -> List[dict]:
    """
    Validate partial decryptions and pick threshold many of them
    Args:
        keys (dict): public key having threshold parameters
        partial_decryptions (list of dict): partial decryptions of shareholders
        verify (callable): checks the proof of a partial decryption. Partial decryptions
            with invalid proofs are discarded if this is set.
    Returns:
        selected partial decryptions (list of dict)
    """
    public_key = keys["public_key"]
    threshold = public_key.get("threshold")
    parties = public_key.get("parties")
    if threshold is None or parties is None:
        raise ValueError(
            "Public key does not have threshold parameters. "
            "Generate threshold keys first."
        )

    selected: Dict[int, dict] = {}
    for partial_decryption in partial_decryptions:
        if verify is not None and verify(partial_decryption) is False:
            logger.warn(
                f"Partial decryption of party {partial_decryption.get('index')} has"
                " an invalid proof. It is discarded."
            )
            continue
        index = partial_decryption["index"]
        if not 1 <= index <= parties:
            raise ValueError(f"Index of partial decryption must be in [1, {parties}], got {index}")
        if index in selected:
            if selected[index]["value"] != partial_decryption["value"]:
                raise ValueError(f"Conflicting partial decryptions for index {index}")
            continue
        selected[index] = partial_decryption

    if len(selected) < threshold:
        raise ValueError(
            f"At least {threshold} valid partial decryptions from distinct parties are"
            f" required, got {len(selected)}"
        )

    return list(selected.values())[:threshold]


def share_paillier_key(
    n: int, phi: int, s: int, threshold: int, parties: int
) -> Dict[int, int]:
    """
    Share the decryption exponent of Paillier and Damgard-Jurik. The exponent d
        satisfies d = 0 mod phi and d = 1 mod n^s, so c^d = (1 + n)^m.
    Args:
        n (int): public modulus
        phi (int): euler's totient of n
        s (int): ciphertext modulo is n^(s+1)
        threshold (int): minimum number of shareholders required to decrypt
        parties (int): total number of shareholders
    Returns:
        shares (dict): party index to its share
    """
    if math.gcd(math.factorial(parties), n) != 1:
        raise ValueError(f"Number of parties {parties} is too large for the modulus")
    n_s = pow(n, s)
    d = phi * pow(phi, -1, n_s)
    # order of the multiplicative group of n^(s+1)
    return split_secret(secret=d, threshold=threshold, parties=parties, modulo=n_s * phi)


def generate_safe_paillier_keys(key_size: int, max_tries: int, s: Optional[int] = None) -> dict:
    """
    Generate Paillier or Damgard-Jurik keys with n = p * q for safe primes p = 2p' + 1 and
        q = 2q' + 1. Then, the group of squares modulo n^(s+1) is cyclic, which partial
        decryptions are proven in. Key format is the same as regular keys.
    Args:
        key_size (int): bit length of n
        max_tries (int): maximum attempts to find safe primes
        s (int): Damgard-Jurik only, ciphertext modulo is n^(s+1)
    Returns:
        keys (dict): private - public key pair
    """
    p = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
    q = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
    while q == p:
        q = find_safe_prime(bits=key_size // 2, max_tries=max_tries)
    n = p * q
    public_key = {"g": 1 + n, "n": n}
    if s is not None:
        public_key["s"] = s
    return {"private_key": {"phi": (p - 1) * (q - 1)}, "public_key": public_key}


def is_safe_paillier_key(n: int, phi: int) -> bool:
    """
    Check whether n is a product of two safe primes, restoring them from n and phi
    Args:
        n (int): public modulus
        phi (int): euler's totient of n
    Returns:
        is safe (bool)
    """
    # p + q = n - phi + 1, and p, q are roots of x^2 - (p + q) x + n
    total = n - phi + 1
    discriminant = total * total - 4 * n
    if discriminant < 0:
        return False
    root = math.isqrt(discriminant)
    if root * root != discriminant:
        return False
    p, q = (total + root) // 2, (total - root) // 2
    return (
        p * q == n
        and p % 2 == 1
        and q % 2 == 1
        and sympy.isprime((p - 1) // 2)
        and sympy.isprime((q - 1) // 2)
    )


def generate_paillier_threshold_keys(
    keys: dict, s: int, modulo: int, threshold: int, parties: int
) -> List[dict]:
    """
    Split the private key of Paillier or Damgard-Jurik into shares. If n is a product
        of safe primes, verification keys v^(delta * share) are published to prove
        partial decryptions.
    Args:
        keys (dict): private - public key pair of the dealer. It is updated in place.
        s (int): ciphertext modulo is n^(s+1)
        modulo (int): ciphertext modulo n^(s+1)
        threshold (int): minimum number of shareholders required to decrypt
        parties (int): total number of shareholders
    Returns:
        keys of shareholders (list of dict)
    """
    n = keys["public_key"]["n"]
    phi = keys["private_key"]["phi"]
    shares = share_paillier_key(n=n, phi=phi, s=s, threshold=threshold, parties=parties)

    verification_keys = None
    if is_safe_paillier_key(n=n, phi=phi):
        # a random square generates the cyclic group of squares with high probability
        r = random.randint(2, modulo - 1)
        while math.gcd(r, n) != 1:
            r = random.randint(2, modulo - 1)
        v = pow(r, 2, modulo)
        delta = math.factorial(parties)
        keys["public_key"]["verification_base"] = v
        verification_keys = [
            pow(v, delta * shares[index], modulo) for index in range(1, parties + 1)
        ]

    return build_share_keys(
        keys=keys,
        shares=shares,
        threshold=threshold,
        parties=parties,
        verification_keys=verification_keys,
    )


def paillier_partial_decrypt(
    keys: dict, ciphertext: int, modulo: int, prove: bool, domain: str
) -> dict:
    """
    Decrypt a Paillier or Damgard-Jurik ciphertext partially. Keys with verification
        keys compute c^(2 * delta * share) as Shoup does, and can prove it.
    Args:
        keys (dict): keys of the shareholder
        ciphertext (int): encrypted message
        modulo (int): ciphertext modulo n^(s+1)
        prove (bool): attach a proof of correct partial decryption
        domain (str): name of the statement being proven
    Returns:
        partial decryption (dict)
    """
    threshold_key = get_threshold_key(keys)
    index = threshold_key["index"]
    share = threshold_key["share"]
    public_key = keys["public_key"]

    if public_key.get("verification_base") is None:
        if prove is True:
            raise ValueError(SAFE_PRIMES_REQUIRED_MSG)
        return {"index": index, "value": pow(ciphertext, share, modulo)}

    delta = math.factorial(public_key["parties"])
    value = pow(ciphertext, 2 * delta * share, modulo)
    if prove is False:
        return {"index": index, "value": value}

    n = public_key["n"]
    proof = zkp.prove_dleq_unknown_order(
        n=n,
        modulo=modulo,
        g1=pow(ciphertext, 4, modulo),
        h1=pow(value, 2, modulo),
        g2=public_key["verification_base"],
        h2=public_key["verification_keys"][index - 1],
        x=delta * share,
        x_bits=(delta * modulo).bit_length(),
        domain=domain,
        context=[index, ciphertext],
    )
    return {"index": index, "value": value, "proof": proof}


def verify_paillier_partial_decryption(
    keys: dict, ciphertext: int, partial_decryption: dict, modulo: int, domain: str
) -> bool:
    """
    Verify that a partial decryption of Paillier or Damgard-Jurik is computed with
        the share of its shareholder
    Args:
        keys (dict): public key having verification keys
        ciphertext (int): encrypted message
        partial_decryption (dict): output of paillier_partial_decrypt with prove=True
        modulo (int): ciphertext modulo n^(s+1)
        domain (str): name of the statement being proven
    Returns:
        is valid (bool)
    """
    public_key = keys["public_key"]
    if public_key.get("verification_base") is None:
        raise ValueError(SAFE_PRIMES_REQUIRED_MSG)
    verification_keys = public_key["verification_keys"]
    try:
        index = partial_decryption["index"]
        value = partial_decryption["value"]
        if not isinstance(index, int) or not 1 <= index <= len(verification_keys):
            return False
        if not isinstance(value, int) or not 0 < value < modulo:
            return False
        delta = math.factorial(public_key["parties"])
        return zkp.verify_dleq_unknown_order(
            n=public_key["n"],
            modulo=modulo,
            g1=pow(ciphertext, 4, modulo),
            h1=pow(value, 2, modulo),
            g2=public_key["verification_base"],
            h2=verification_keys[index - 1],
            proof=partial_decryption["proof"],
            x_bits=(delta * modulo).bit_length(),
            domain=domain,
            context=[index, ciphertext],
        )
    except (KeyError, TypeError, ValueError):
        return False


def combine_paillier_partial_decryptions(
    keys: dict,
    ciphertext: int,
    partial_decryptions: List[dict],
    modulo: int,
    verify: bool,
    domain: str,
) -> int:
    """
    Combine partial decryptions of Paillier and Damgard-Jurik. Order of the group is
        secret, so lagrange coefficients are scaled with delta = parties! to be integers.
    Args:
        keys (dict): public key having threshold parameters
        ciphertext (int): encrypted message
        partial_decryptions (list of dict): partial decryptions of shareholders
        modulo (int): ciphertext modulo n^(s+1)
        verify (bool): check proofs and discard invalid or unproven partial decryptions
        domain (str): name of the statement being proven
    Returns:
        plaintext (int): restored message in modulo n
    """
    public_key = keys["public_key"]
    verifiable = public_key.get("verification_base") is not None
    if verify is True and verifiable is False:
        raise ValueError(SAFE_PRIMES_REQUIRED_MSG)

    selected = select_partial_decryptions(
        keys=keys,
        partial_decryptions=partial_decryptions,
        verify=(
            (
                lambda partial_decryption: verify_paillier_partial_decryption(
                    keys=keys,
                    ciphertext=ciphertext,
                    partial_decryption=partial_decryption,
                    modulo=modulo,
                    domain=domain,
                )
            )
            if verify is True
            else None
        ),
    )

    n = public_key["n"]
    delta = math.factorial(public_key["parties"])
    indices = [partial_decryption["index"] for partial_decryption in selected]

    # c^(delta * d) = (1 + n)^(delta * m) for regular partial decryptions, and
    # c^(4 * delta^2 * d) = (1 + n)^(4 * delta^2 * m) for c^(2 * delta * share)
    exponent = 2 if verifiable else 1
    factor = 4 * delta * delta if verifiable else delta

    combined = 1
    for partial_decryption in selected:
        coefficient = scaled_lagrange_coefficient(
            index=partial_decryption["index"], indices=indices, delta=delta
        )
        combined = (
            combined * pow(partial_decryption["value"], exponent * coefficient, modulo)
        ) % modulo

    factor_m = ((combined - 1) // n) % n
    return (factor_m * pow(factor, -1, n)) % n
