import copy
import json

import pytest

from lightphe import LightPHE
from lightphe.commons import zkp
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_range_proof.py")

ALGORITHMS = [
    ("Exponential-ElGamal", 128, True),
    ("EllipticCurve-ElGamal", None, False),
    ("Paillier", 128, False),
    ("Damgard-Jurik", 128, False),
]


def build(algorithm_name: str, key_size, prime_order: bool) -> LightPHE:
    return LightPHE(algorithm_name=algorithm_name, key_size=key_size, prime_order=prime_order)


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", ALGORITHMS)
def test_range_proof(algorithm_name, key_size, prime_order, tmp_path):
    cs = build(algorithm_name, key_size, prime_order)

    # prover and verifier have the public key only
    public_file = str(tmp_path / "public.json")
    cs.export_keys(target_file=public_file, public=True)
    public_cs = LightPHE(algorithm_name=algorithm_name, key_file=public_file)

    low, high = 10, 200
    for plaintext in [low, 137, high]:
        c, proof = public_cs.encrypt_with_range_proof(plaintext, low=low, high=high, context="alice")
        proof = json.loads(json.dumps(proof))
        assert cs.decrypt(c) == plaintext
        assert public_cs.verify_range(c, proof, low=low, high=high, context="alice") is True

    # proof is bound to its context, range and ciphertext
    assert public_cs.verify_range(c, proof, low=low, high=high, context="bob") is False
    assert public_cs.verify_range(c, proof, low=low, high=high) is False
    assert public_cs.verify_range(c, proof, low=low - 1, high=high, context="alice") is False
    assert public_cs.verify_range(c, proof, low=low, high=high + 1, context="alice") is False
    assert public_cs.verify_range(c + c, proof, low=low, high=high, context="alice") is False
    other_c, _ = public_cs.encrypt_with_range_proof(plaintext, low=low, high=high, context="alice")
    assert public_cs.verify_range(other_c, proof, low=low, high=high, context="alice") is False

    # tampered, reordered, truncated and malformed proofs are rejected
    reordered = copy.deepcopy(proof)
    reordered["ciphertexts"][1], reordered["ciphertexts"][2] = (
        reordered["ciphertexts"][2],
        reordered["ciphertexts"][1],
    )
    reordered["proofs"][1], reordered["proofs"][2] = reordered["proofs"][2], reordered["proofs"][1]
    assert public_cs.verify_range(c, reordered, low=low, high=high, context="alice") is False

    truncated = {key: value[:-1] for key, value in proof.items()}
    assert public_cs.verify_range(c, truncated, low=low, high=high, context="alice") is False

    tampered = copy.deepcopy(proof)
    tampered["proofs"][1]["challenges"][0] += 1
    assert public_cs.verify_range(c, tampered, low=low, high=high, context="alice") is False

    assert public_cs.verify_range(c, {}, low=low, high=high, context="alice") is False
    assert public_cs.verify_range(c, None, low=low, high=high, context="alice") is False

    logger.info(f"✅ Range proof test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", ALGORITHMS)
def test_out_of_range_ciphertext_is_rejected(algorithm_name, key_size, prime_order):
    """
    A cheater runs the prover for a value out of the range, or presents the proof of
        an in-range value next to the ciphertext of an out-of-range value
    """
    cs = build(algorithm_name, key_size, prime_order)
    low, high = 0, 100
    values = [0, 0, 1]

    # decomposition cannot represent 150 with bits of [0, 100], so restored ciphertext
    # does not encrypt 150, and the ciphertext of 150 does not match it
    out_of_range = cs.encrypt(150)
    _, proof = zkp.prove_range(cs.cs, 150, low, high, values, context=None)
    assert cs.verify_range(out_of_range, proof, low=low, high=high) is False

    _, proof = cs.encrypt_with_range_proof(50, low=low, high=high)
    assert cs.verify_range(out_of_range, proof, low=low, high=high) is False


def test_edge_ranges():
    cs = LightPHE(algorithm_name="Paillier", key_size=128)
    modulo = cs.cs.plaintext_modulo

    # single value range
    c, proof = cs.encrypt_with_range_proof(7, low=7, high=7)
    assert cs.verify_range(c, proof, low=7, high=7) is True
    assert cs.decrypt(c) == 7

    # ranges with negative values decrypt to modulo - x as encrypt does
    c, proof = cs.encrypt_with_range_proof(-30, low=-100, high=100)
    assert cs.verify_range(c, proof, low=-100, high=100) is True
    assert cs.decrypt(c) == modulo - 30

    # power of two widths
    for high in [1, 2, 255, 256]:
        c, proof = cs.encrypt_with_range_proof(high, low=0, high=high)
        assert cs.verify_range(c, proof, low=0, high=high) is True

    # invalid inputs
    with pytest.raises(ValueError, match="must be in"):
        cs.encrypt_with_range_proof(101, low=0, high=100)
    with pytest.raises(ValueError, match="must be in"):
        cs.encrypt_with_range_proof(-1, low=0, high=100)
    with pytest.raises(ValueError, match="must not be greater"):
        cs.encrypt_with_range_proof(5, low=10, high=0)
    with pytest.raises(ValueError, match="must be integers"):
        cs.encrypt_with_range_proof(5, low=0, high=10.5)
    with pytest.raises(ValueError, match="narrower"):
        cs.encrypt_with_range_proof(5, low=0, high=modulo)


def test_unsupported_algorithms():
    cs = LightPHE(algorithm_name="ElGamal", key_size=128, prime_order=True)
    with pytest.raises(ValueError, match="Use Exponential-ElGamal instead"):
        cs.encrypt_with_range_proof(5, low=1, high=10)

    cs = LightPHE(algorithm_name="Exponential-ElGamal", key_size=50)
    with pytest.raises(ValueError, match="prime_order=True"):
        cs.encrypt_with_range_proof(5, low=0, high=10)

    for algorithm_name in ["RSA", "Okamoto-Uchiyama"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        with pytest.raises(ValueError, match="does not support proving"):
            cs.encrypt_with_range_proof(5, low=0, high=10)


def test_salary_survey():
    """
    Employees submit encrypted salaries with proofs that they are in [0, 500000].
        Invalid submissions are rejected, so nobody can skew the average, and the
        authority decrypts only the total of valid salaries.
    """
    authority_cs = LightPHE(algorithm_name="Paillier", key_size=128)
    public_cs = LightPHE(
        algorithm_name="Paillier", keys={"public_key": authority_cs.cs.keys["public_key"]}
    )
    low, high = 0, 500000

    salaries = {"alice": 85000, "bob": 62000, "carol": 120000, "dave": 47000}
    submissions = {
        employee: public_cs.encrypt_with_range_proof(salary, low=low, high=high, context=employee)
        for employee, salary in salaries.items()
    }

    # mallory copies alice's submission
    submissions["mallory"] = submissions["alice"]

    # oscar cannot prove a huge salary, and cannot reuse a proof of a valid salary
    with pytest.raises(ValueError, match="must be in"):
        public_cs.encrypt_with_range_proof(10**9, low=low, high=high, context="oscar")
    _, oscar_proof = public_cs.encrypt_with_range_proof(50000, low=low, high=high, context="oscar")
    submissions["oscar"] = (public_cs.encrypt(10**9), oscar_proof)

    # trent cannot submit a negative salary either
    _, trent_proof = public_cs.encrypt_with_range_proof(0, low=low, high=high, context="trent")
    submissions["trent"] = (public_cs.encrypt(-(10**6)), trent_proof)

    valid = [
        c
        for employee, (c, proof) in submissions.items()
        if public_cs.verify_range(c, proof, low=low, high=high, context=employee)
    ]
    assert len(valid) == len(salaries)

    total = valid[0]
    for c in valid[1:]:
        total = total + c

    # authority decrypts the total only with a proof, and anyone verifies it
    result, proof = authority_cs.decrypt_with_proof(total)
    assert public_cs.verify_decryption(total, result, proof) is True
    assert result == sum(salaries.values())
    assert result / len(valid) == 78500

    logger.info("✅ Salary survey test succeeded")
