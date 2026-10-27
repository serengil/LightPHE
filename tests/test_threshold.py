import itertools
import json

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_threshold.py")

THRESHOLD = 3
PARTIES = 5

ADDITIVE_ALGORITHMS = [
    ("Exponential-ElGamal", 50),
    ("EllipticCurve-ElGamal", None),
    ("Paillier", 50),
    ("Damgard-Jurik", 50),
]


def build(algorithm_name: str, key_size=None):
    """
    Build a dealer, a public cryptosystem with threshold parameters and shareholders
    """
    dealer_cs = LightPHE(
        algorithm_name=algorithm_name,
        key_size=key_size,
        prime_order=algorithm_name in ["ElGamal", "Exponential-ElGamal"],
    )
    share_keys = dealer_cs.generate_threshold_keys(threshold=THRESHOLD, parties=PARTIES)
    shareholders = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]
    return dealer_cs, shareholders


@pytest.mark.parametrize("algorithm_name,key_size", ADDITIVE_ALGORITHMS)
def test_additive_threshold_decryption(algorithm_name, key_size):
    dealer_cs, shareholders = build(algorithm_name, key_size)

    m1, m2, k = 17, 21, 3
    c1 = dealer_cs.encrypt(m1)
    c2 = dealer_cs.encrypt(m2)

    # homomorphic operations before threshold decryption
    for c, expected in [(c1, m1), (c1 + c2, m1 + m2), (c1 * k, m1 * k)]:
        partials = [shareholder.partial_decrypt(c) for shareholder in shareholders]

        # any threshold many shareholders can decrypt
        for subset in itertools.combinations(partials, THRESHOLD):
            assert dealer_cs.combine_partial_decryptions(c, list(subset)) == expected

        # more than threshold many partial decryptions are fine as well
        assert dealer_cs.combine_partial_decryptions(c, partials) == expected

        # less than threshold many partial decryptions are rejected
        with pytest.raises(ValueError, match="At least"):
            dealer_cs.combine_partial_decryptions(c, partials[: THRESHOLD - 1])

    # regenerated ciphertexts are decrypted as well
    c3 = dealer_cs.regenerate_ciphertext(c1)
    partials = [shareholder.partial_decrypt(c3) for shareholder in shareholders[:THRESHOLD]]
    assert dealer_cs.combine_partial_decryptions(c3, partials) == m1

    logger.info(f"✅ Threshold decryption test succeeded for {algorithm_name}")


def test_multiplicative_elgamal_threshold_decryption():
    dealer_cs, shareholders = build("ElGamal", 50)

    m1, m2 = 17, 21
    c = dealer_cs.encrypt(m1) * dealer_cs.encrypt(m2)

    partials = [shareholder.partial_decrypt(c) for shareholder in shareholders]
    for subset in itertools.combinations(partials, THRESHOLD):
        assert dealer_cs.combine_partial_decryptions(c, list(subset)) == m1 * m2


@pytest.mark.parametrize("algorithm_name", ["Paillier", "Damgard-Jurik"])
def test_negative_and_float_values(algorithm_name):
    dealer_cs, shareholders = build(algorithm_name, 50)
    modulo = dealer_cs.cs.plaintext_modulo

    c = dealer_cs.encrypt(-5)
    partials = [shareholder.partial_decrypt(c) for shareholder in shareholders[:THRESHOLD]]
    assert dealer_cs.combine_partial_decryptions(c, partials) == modulo - 5

    # float is restored as dividend * divisor^-1 mod modulo, same as decrypt
    c = dealer_cs.encrypt(1.5)
    partials = [shareholder.partial_decrypt(c) for shareholder in shareholders[:THRESHOLD]]
    assert dealer_cs.combine_partial_decryptions(c, partials) == (15 * pow(10, -1, modulo)) % modulo


def test_tensors():
    dealer_cs, shareholders = build("Paillier", 128)

    tensor = [1.005, 2.05, -3.5, 4, 0]
    encrypted = dealer_cs.encrypt(tensor, silent=True)

    partials = [shareholder.partial_decrypt(encrypted) for shareholder in shareholders[1:4]]
    restored = dealer_cs.combine_partial_decryptions(encrypted, partials)
    assert restored == pytest.approx(tensor, abs=1e-3)


def test_private_key_is_dropped_and_public_key_is_shared(tmp_path):
    dealer_cs, shareholders = build("Paillier", 50)

    # dealer forgets the private key
    assert dealer_cs.cs.keys.get("private_key") is None
    with pytest.raises(ValueError, match="private key"):
        dealer_cs.decrypt(dealer_cs.encrypt(1))

    # shareholders cannot decrypt alone, and do not have the private key
    c = dealer_cs.encrypt(42)
    for shareholder in shareholders:
        assert shareholder.cs.keys.get("private_key") is None
        with pytest.raises(ValueError, match="private key"):
            shareholder.decrypt(c)

    # dealer cannot generate threshold keys again
    with pytest.raises(ValueError, match="private key"):
        dealer_cs.generate_threshold_keys(threshold=THRESHOLD, parties=PARTIES)

    # anyone having the exported public key can combine partial decryptions
    public_file = str(tmp_path / "public.json")
    dealer_cs.export_keys(target_file=public_file, public=True)
    public_cs = LightPHE(algorithm_name="Paillier", key_file=public_file)
    with pytest.raises(ValueError, match="threshold key"):
        public_cs.partial_decrypt(c)

    # keys of shareholders and partial decryptions survive json round trip
    share_file = str(tmp_path / "share.json")
    shareholders[0].export_keys(target_file=share_file)
    restored_shareholder = LightPHE(algorithm_name="Paillier", key_file=share_file)
    partials = [restored_shareholder.partial_decrypt(c)] + [
        shareholder.partial_decrypt(c) for shareholder in shareholders[1:THRESHOLD]
    ]
    partials = json.loads(json.dumps(partials))
    assert public_cs.combine_partial_decryptions(c, partials) == 42


def test_invalid_inputs():
    dealer_cs, shareholders = build("Paillier", 50)
    c = dealer_cs.encrypt(7)
    partials = [shareholder.partial_decrypt(c) for shareholder in shareholders]

    # same party counted once
    with pytest.raises(ValueError, match="distinct"):
        dealer_cs.combine_partial_decryptions(c, [partials[0]] * THRESHOLD)

    # conflicting partial decryptions of same party
    forged = {"index": partials[0]["index"], "value": partials[0]["value"] + 1}
    with pytest.raises(ValueError, match="Conflicting"):
        dealer_cs.combine_partial_decryptions(c, [partials[0], forged, partials[1]])

    # unknown party
    with pytest.raises(ValueError, match="Index"):
        dealer_cs.combine_partial_decryptions(
            c, partials[:2] + [{"index": PARTIES + 1, "value": 1}]
        )

    for threshold, parties in [(0, 5), (6, 5)]:
        cs = LightPHE(algorithm_name="Paillier", key_size=50)
        with pytest.raises(ValueError):
            cs.generate_threshold_keys(threshold=threshold, parties=parties)


def test_threshold_of_one_and_all_parties():
    for threshold, parties in [(1, 3), (3, 3)]:
        dealer_cs = LightPHE(
            algorithm_name="Exponential-ElGamal", key_size=50, prime_order=True
        )
        share_keys = dealer_cs.generate_threshold_keys(threshold=threshold, parties=parties)
        shareholders = [
            LightPHE(algorithm_name="Exponential-ElGamal", keys=keys) for keys in share_keys
        ]
        c = dealer_cs.encrypt(10)
        partials = [shareholder.partial_decrypt(c) for shareholder in shareholders]
        assert dealer_cs.combine_partial_decryptions(c, partials[:threshold]) == 10


def test_elgamal_keys_without_prime_order_are_rejected():
    for algorithm_name in ["ElGamal", "Exponential-ElGamal"]:
        # default key generation is unchanged and does not have q
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        assert "q" not in cs.cs.keys["public_key"]
        with pytest.raises(ValueError, match="prime_order=True"):
            cs.generate_threshold_keys(threshold=THRESHOLD, parties=PARTIES)

        # private key is kept if threshold keys cannot be generated
        c = cs.encrypt(2)
        assert cs.decrypt(c) == 2


def test_prime_order_elgamal_keys():
    for algorithm_name in ["ElGamal", "Exponential-ElGamal"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50, prime_order=True)
        public_key = cs.cs.keys["public_key"]
        p, g, q = public_key["p"], public_key["g"], public_key["q"]
        assert (p - 1) % q == 0
        assert g != 1 and pow(g, q, p) == 1

        # classic usage works with prime order keys as well
        c1, c2 = cs.encrypt(17), cs.encrypt(21)
        if algorithm_name == "ElGamal":
            assert cs.decrypt(c1 * c2) == 17 * 21
        else:
            assert cs.decrypt(c1 + c2) == 17 + 21
            assert cs.decrypt(c1 * 3) == 17 * 3


def test_unsupported_algorithms():
    for algorithm_name in ["RSA", "Okamoto-Uchiyama", "Goldwasser-Micali"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        with pytest.raises(ValueError, match="does not support threshold decryption"):
            cs.generate_threshold_keys(threshold=THRESHOLD, parties=PARTIES)
