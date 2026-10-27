import copy
import json

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_zkp.py")

ALGORITHMS = [
    ("ElGamal", 128, True),
    ("Exponential-ElGamal", 128, True),
    ("EllipticCurve-ElGamal", None, False),
    ("Paillier", 128, False),
    ("Damgard-Jurik", 128, False),
]

ELGAMAL_FAMILY = ["ElGamal", "Exponential-ElGamal", "EllipticCurve-ElGamal"]


def build(algorithm_name: str, key_size, prime_order: bool) -> LightPHE:
    return LightPHE(algorithm_name=algorithm_name, key_size=key_size, prime_order=prime_order)


def compute(cs: LightPHE, algorithm_name: str, m1: int, m2: int):
    """
    Combine two encrypted values homomorphically, and return the expected plaintext
    """
    if algorithm_name == "ElGamal":
        return cs.encrypt(m1) * cs.encrypt(m2), m1 * m2
    return cs.encrypt(m1) + cs.encrypt(m2), m1 + m2


def tamper(proof: dict) -> dict:
    tampered = copy.deepcopy(proof)
    key = next(iter(tampered))
    if isinstance(tampered[key], list):
        tampered[key][0] += 1
    else:
        tampered[key] = tampered[key] + 1
    return tampered


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", ALGORITHMS)
def test_proof_of_correct_decryption(algorithm_name, key_size, prime_order, tmp_path):
    cs = build(algorithm_name, key_size, prime_order)
    c, expected = compute(cs, algorithm_name, 17, 3)

    plaintext, proof = cs.decrypt_with_proof(c)
    assert plaintext == expected == cs.decrypt(c)
    assert cs.verify_decryption(c, plaintext, proof) is True

    # verifier has the public key only, and proof survives json round trip
    public_file = str(tmp_path / "public.json")
    cs.export_keys(target_file=public_file, public=True)
    verifier_cs = LightPHE(algorithm_name=algorithm_name, key_file=public_file)
    proof = json.loads(json.dumps(proof))
    assert verifier_cs.verify_decryption(c, plaintext, proof) is True

    # wrong plaintext, tampered proof and malformed proof are rejected
    assert verifier_cs.verify_decryption(c, plaintext + 1, proof) is False
    assert verifier_cs.verify_decryption(c, plaintext, tamper(proof)) is False
    assert verifier_cs.verify_decryption(c, plaintext, {}) is False
    assert verifier_cs.verify_decryption(c, plaintext, None) is False
    assert verifier_cs.verify_decryption(c, str(plaintext), proof) is False

    # proof of a ciphertext does not prove another ciphertext of same plaintext
    c_prime = cs.regenerate_ciphertext(c)
    assert verifier_cs.verify_decryption(c_prime, plaintext, proof) is False
    plaintext_prime, proof_prime = cs.decrypt_with_proof(c_prime)
    assert plaintext_prime == plaintext
    assert verifier_cs.verify_decryption(c_prime, plaintext, proof_prime) is True

    logger.info(f"✅ Proof of correct decryption test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name", ["ElGamal", "Exponential-ElGamal"])
def test_elgamal_proofs_require_prime_order(algorithm_name):
    cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
    c = cs.encrypt(5)
    with pytest.raises(ValueError, match="prime_order=True"):
        cs.decrypt_with_proof(c)
    with pytest.raises(ValueError, match="prime_order=True"):
        cs.verify_decryption(c, 5, {"challenge": 1, "response": 1})


def test_ciphertext_out_of_group_is_rejected():
    cs = LightPHE(algorithm_name="Exponential-ElGamal", key_size=128, prime_order=True)
    c = cs.encrypt(5)
    plaintext, proof = cs.decrypt_with_proof(c)

    # -c1 is not in the subgroup of prime order q
    p = cs.cs.keys["public_key"]["p"]
    c1, c2 = c.value
    forged = cs.create_ciphertext_obj((p - c1, c2))
    assert cs.verify_decryption(forged, plaintext, proof) is False


def test_unsupported_algorithms():
    for algorithm_name in ["RSA", "Okamoto-Uchiyama"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        c = cs.encrypt(5)
        with pytest.raises(ValueError, match="does not support proofs of correct decryption"):
            cs.decrypt_with_proof(c)
        with pytest.raises(ValueError, match="does not support proofs of correct decryption"):
            cs.verify_decryption(c, 5, {})


@pytest.mark.parametrize("algorithm_name", ELGAMAL_FAMILY)
def test_verifiable_partial_decryptions(algorithm_name):
    threshold, parties = 3, 5
    dealer_cs = LightPHE(
        algorithm_name=algorithm_name,
        key_size=None if algorithm_name == "EllipticCurve-ElGamal" else 128,
        prime_order=algorithm_name != "EllipticCurve-ElGamal",
    )
    share_keys = dealer_cs.generate_threshold_keys(threshold=threshold, parties=parties)
    shareholders = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]

    c, expected = compute(dealer_cs, algorithm_name, 17, 3)
    partials = json.loads(json.dumps([s.partial_decrypt(c, prove=True) for s in shareholders]))

    for partial in partials:
        assert dealer_cs.verify_partial_decryption(c, partial) is True

    # a cheating shareholder sends a wrong value with its old proof
    honest = partials[0]
    if algorithm_name == "EllipticCurve-ElGamal":
        forged_value = shareholders[1].partial_decrypt(c, prove=True)["value"]
    else:
        p = dealer_cs.cs.keys["public_key"]["p"]
        forged_value = (honest["value"] * dealer_cs.cs.keys["public_key"]["g"]) % p
    forged = {**honest, "value": forged_value}
    assert dealer_cs.verify_partial_decryption(c, forged) is False

    # a proof cannot be reused under another index or for another ciphertext
    assert dealer_cs.verify_partial_decryption(c, {**honest, "index": 2}) is False
    assert dealer_cs.verify_partial_decryption(c, {**honest, "index": parties + 1}) is False
    other_c = dealer_cs.regenerate_ciphertext(c)
    assert dealer_cs.verify_partial_decryption(other_c, honest) is False
    assert dealer_cs.verify_partial_decryption(c, {**honest, "proof": None}) is False

    # invalid partial decryptions are discarded if enough valid ones remain
    assert (
        dealer_cs.combine_partial_decryptions(c, [forged] + partials[1:4], verify=True)
        == expected
    )

    # otherwise combination fails instead of returning a wrong plaintext
    with pytest.raises(ValueError, match="valid partial decryptions"):
        dealer_cs.combine_partial_decryptions(c, [forged] + partials[1:3], verify=True)

    # partial decryptions without proofs are discarded if verification is on
    unproven = [s.partial_decrypt(c) for s in shareholders]
    with pytest.raises(ValueError, match="valid partial decryptions"):
        dealer_cs.combine_partial_decryptions(c, unproven, verify=True)

    logger.info(f"✅ Verifiable partial decryption test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name", ELGAMAL_FAMILY)
def test_partial_decryption_proofs_are_opt_in(algorithm_name):
    dealer_cs = LightPHE(
        algorithm_name=algorithm_name,
        key_size=None if algorithm_name == "EllipticCurve-ElGamal" else 128,
        prime_order=algorithm_name != "EllipticCurve-ElGamal",
    )
    share_keys = dealer_cs.generate_threshold_keys(threshold=2, parties=3)
    shareholders = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]
    c, expected = compute(dealer_cs, algorithm_name, 17, 3)

    # no proofs by default, and combination does not check them by default
    partials = [s.partial_decrypt(c) for s in shareholders]
    assert all("proof" not in partial for partial in partials)
    assert dealer_cs.combine_partial_decryptions(c, partials) == expected

    # proven partial decryptions are combined with or without verification
    proven = [s.partial_decrypt(c, prove=True) for s in shareholders]
    assert dealer_cs.combine_partial_decryptions(c, proven) == expected
    assert dealer_cs.combine_partial_decryptions(c, proven, verify=True) == expected

    # without verification, a cheating shareholder causes a wrong plaintext silently.
    # additive variants would brute force a huge discrete logarithm, so check ElGamal only.
    if algorithm_name == "ElGamal":
        p = dealer_cs.cs.keys["public_key"]["p"]
        forged = {**partials[0], "value": (partials[0]["value"] * 2) % p}
        assert dealer_cs.combine_partial_decryptions(c, [forged, partials[1]]) != expected


@pytest.mark.parametrize("algorithm_name", ["Paillier", "Damgard-Jurik"])
def test_paillier_partial_decryption_proofs_require_safe_primes(algorithm_name):
    dealer_cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
    share_keys = dealer_cs.generate_threshold_keys(threshold=2, parties=3)
    shareholder = LightPHE(algorithm_name=algorithm_name, keys=share_keys[0])
    c = dealer_cs.encrypt(5)

    # regular keys still decrypt without proofs
    partials = [LightPHE(algorithm_name=algorithm_name, keys=k).partial_decrypt(c) for k in share_keys]
    assert dealer_cs.combine_partial_decryptions(c, partials) == 5

    with pytest.raises(ValueError, match="safe_primes=True"):
        shareholder.partial_decrypt(c, prove=True)
    with pytest.raises(ValueError, match="safe_primes=True"):
        dealer_cs.verify_partial_decryption(c, shareholder.partial_decrypt(c))
    with pytest.raises(ValueError, match="safe_primes=True"):
        dealer_cs.combine_partial_decryptions(c, partials, verify=True)


@pytest.mark.parametrize("algorithm_name", ["Paillier", "Damgard-Jurik"])
def test_verifiable_paillier_partial_decryptions(algorithm_name, tmp_path):
    threshold, parties = 3, 5
    dealer_cs = LightPHE(algorithm_name=algorithm_name, key_size=128, safe_primes=True)

    # safe prime keys work as regular keys
    c = dealer_cs.encrypt(100) + dealer_cs.encrypt(50)
    assert dealer_cs.decrypt(c) == 150
    assert dealer_cs.decrypt(c * 3) == 450

    share_keys = dealer_cs.generate_threshold_keys(threshold=threshold, parties=parties)

    # keys of shareholders survive exporting and restoring
    shareholders = []
    for k, keys in enumerate(share_keys):
        key_file = str(tmp_path / f"share_{k}.json")
        LightPHE(algorithm_name=algorithm_name, keys=keys).export_keys(target_file=key_file)
        shareholders.append(LightPHE(algorithm_name=algorithm_name, key_file=key_file))

    partials = json.loads(json.dumps([s.partial_decrypt(c, prove=True) for s in shareholders]))
    for partial in partials:
        assert dealer_cs.verify_partial_decryption(c, partial) is True
    assert dealer_cs.combine_partial_decryptions(c, partials, verify=True) == 150

    # partial decryptions without proofs are combined if verification is off
    unproven = [s.partial_decrypt(c) for s in shareholders]
    assert all("proof" not in partial for partial in unproven)
    assert dealer_cs.combine_partial_decryptions(c, unproven) == 150
    with pytest.raises(ValueError, match="valid partial decryptions"):
        dealer_cs.combine_partial_decryptions(c, unproven, verify=True)

    # a cheating shareholder multiplies its partial decryption with (1 + n)^shift
    n = dealer_cs.cs.keys["public_key"]["n"]
    modulo = dealer_cs.cs.ciphertext_modulo
    honest = partials[0]
    forged = {**honest, "value": (honest["value"] * (1 + n)) % modulo}
    assert dealer_cs.verify_partial_decryption(c, forged) is False

    # a proof cannot be reused under another index or for another ciphertext
    assert dealer_cs.verify_partial_decryption(c, {**honest, "index": 2}) is False
    assert dealer_cs.verify_partial_decryption(c, {**honest, "index": parties + 1}) is False
    assert dealer_cs.verify_partial_decryption(dealer_cs.regenerate_ciphertext(c), honest) is False
    assert dealer_cs.verify_partial_decryption(c, {**honest, "proof": None}) is False
    assert dealer_cs.verify_partial_decryption(c, {**honest, "proof": tamper(honest["proof"])}) is False

    # invalid partial decryptions are discarded if enough valid ones remain
    assert dealer_cs.combine_partial_decryptions(c, [forged] + partials[1:4], verify=True) == 150
    with pytest.raises(ValueError, match="valid partial decryptions"):
        dealer_cs.combine_partial_decryptions(c, [forged] + partials[1:3], verify=True)

    logger.info(f"✅ Verifiable partial decryption test succeeded for {algorithm_name}")


MEMBERSHIP_ALGORITHMS = [
    ("Exponential-ElGamal", 128, True),
    ("EllipticCurve-ElGamal", None, False),
    ("Paillier", 128, False),
    ("Damgard-Jurik", 128, False),
]


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", MEMBERSHIP_ALGORITHMS)
def test_proof_of_membership(algorithm_name, key_size, prime_order, tmp_path):
    cs = build(algorithm_name, key_size, prime_order)

    # voter has the public key only
    public_file = str(tmp_path / "public.json")
    cs.export_keys(target_file=public_file, public=True)
    voter_cs = LightPHE(algorithm_name=algorithm_name, key_file=public_file)

    for vote in [0, 1]:
        ballot, proof = voter_cs.encrypt_with_proof(vote, context="voter-42")
        proof = json.loads(json.dumps(proof))
        assert cs.decrypt(ballot) == vote
        assert voter_cs.verify_ciphertext(ballot, proof, context="voter-42") is True
        assert voter_cs.verify_ciphertext(ballot, proof, values=[0, 1], context="voter-42")

        # proof is bound to its context, values and ciphertext
        assert voter_cs.verify_ciphertext(ballot, proof, context="voter-43") is False
        assert voter_cs.verify_ciphertext(ballot, proof) is False
        assert voter_cs.verify_ciphertext(ballot, proof, values=[1, 0], context="voter-42") is False
        assert voter_cs.verify_ciphertext(ballot + ballot, proof, context="voter-42") is False
        assert voter_cs.verify_ciphertext(ballot, tamper(proof), context="voter-42") is False
        assert voter_cs.verify_ciphertext(ballot, {}, context="voter-42") is False
        assert voter_cs.verify_ciphertext(ballot, None, context="voter-42") is False

    # larger sets of values, e.g. a rating in [1, 5]
    rating, proof = voter_cs.encrypt_with_proof(4, values=[1, 2, 3, 4, 5])
    assert voter_cs.verify_ciphertext(rating, proof, values=[1, 2, 3, 4, 5]) is True
    assert voter_cs.verify_ciphertext(rating, proof, values=[1, 2, 3, 5, 6]) is False
    assert cs.decrypt(rating) == 4

    # single allowed value
    c, proof = voter_cs.encrypt_with_proof(7, values=[7])
    assert voter_cs.verify_ciphertext(c, proof, values=[7]) is True

    # invalid inputs
    with pytest.raises(ValueError, match="one of the allowed values"):
        voter_cs.encrypt_with_proof(2)
    with pytest.raises(ValueError, match="distinct"):
        voter_cs.encrypt_with_proof(1, values=[0, 1, 1])
    with pytest.raises(ValueError, match="non-empty"):
        voter_cs.encrypt_with_proof(1, values=[])
    with pytest.raises(ValueError, match="non-empty"):
        voter_cs.encrypt_with_proof(1, values=[0, 1.5])

    logger.info(f"✅ Proof of membership test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", MEMBERSHIP_ALGORITHMS)
def test_cheating_voter_is_rejected(algorithm_name, key_size, prime_order):
    """
    A voter encrypts 2 and runs the prover pretending that it encrypts 1
    """
    from lightphe.commons import zkp

    cs = build(algorithm_name, key_size, prime_order)
    keys = cs.cs.keys["public_key"]
    values = [0, 1]
    r = cs.cs.generate_random_key()
    value = cs.cs.encrypt(plaintext=2, random_key=r)

    if algorithm_name in ["Paillier", "Damgard-Jurik"]:
        n = keys["n"]
        modulo = n * n if algorithm_name == "Paillier" else pow(n, keys["s"] + 1)
        domain = (
            "lightphe/paillier/membership"
            if algorithm_name == "Paillier"
            else "lightphe/damgard-jurik/membership"
        )
        proof = zkp.prove_nth_power_or(
            n=n,
            modulo=modulo,
            us=zkp.paillier_membership_candidates(value, values, n, modulo),
            r=r,
            index=1,
            domain=domain,
            context=[values, None],
        )
    else:
        if algorithm_name == "Exponential-ElGamal":
            p, g, y = keys["p"], keys["g"], keys["y"]
            group = zkp.ModularGroup(p=p, q=keys["q"])
            g1, h1, g2 = g, value[0], y
            h2s = [(value[1] * pow(g, -v, p)) % p for v in values]
            domain, context = "lightphe/exponential-elgamal/membership", [p, value[1], values, None]
        else:
            from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

            ecc = cs.cs.ecc
            group = zkp.EllipticCurveGroup(ecc)
            to_point = lambda point: EllipticCurvePoint(point[0], point[1], ecc.curve)
            g1, h1, g2 = ecc.G, to_point(value[0]), to_point(keys["Qa"])
            c2 = to_point(value[1])
            h2s = [c2 if v == 0 else c2 - (ecc.G * v) for v in values]
            domain, context = "lightphe/elliptic-curve-elgamal/membership", [ecc.n, value[1], values, None]
        proof = zkp.prove_dleq_or(
            group=group, g1=g1, h1=h1, g2=g2, h2s=h2s, x=r, index=1, domain=domain, context=context
        )

    ballot = cs.create_ciphertext_obj(value)
    assert cs.decrypt(ballot) == 2
    assert cs.verify_ciphertext(ballot, proof) is False


def test_membership_proofs_unsupported():
    cs = LightPHE(algorithm_name="ElGamal", key_size=128, prime_order=True)
    with pytest.raises(ValueError, match="Use Exponential-ElGamal instead"):
        cs.encrypt_with_proof(1, values=[1, 2])

    cs = LightPHE(algorithm_name="Exponential-ElGamal", key_size=50)
    with pytest.raises(ValueError, match="prime_order=True"):
        cs.encrypt_with_proof(1)

    for algorithm_name in ["RSA", "Okamoto-Uchiyama"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        with pytest.raises(ValueError, match="does not support proving"):
            cs.encrypt_with_proof(1)


KNOWLEDGE_ALGORITHMS = [
    ("ElGamal", 128, True),
    ("Exponential-ElGamal", 128, True),
    ("EllipticCurve-ElGamal", None, False),
    ("Paillier", 128, False),
    ("Damgard-Jurik", 128, False),
]


@pytest.mark.parametrize("algorithm_name,key_size,prime_order", KNOWLEDGE_ALGORITHMS)
def test_proof_of_knowledge(algorithm_name, key_size, prime_order, tmp_path):
    cs = build(algorithm_name, key_size, prime_order)

    # prover and verifier have the public key only
    public_file = str(tmp_path / "public.json")
    cs.export_keys(target_file=public_file, public=True)
    public_cs = LightPHE(algorithm_name=algorithm_name, key_file=public_file)

    c, proof = public_cs.encrypt_with_proof_of_knowledge(17, context="alice")
    proof = json.loads(json.dumps(proof))
    assert cs.decrypt(c) == 17
    assert public_cs.verify_knowledge(c, proof, context="alice") is True

    # proof is bound to its context and ciphertext
    assert public_cs.verify_knowledge(c, proof, context="bob") is False
    assert public_cs.verify_knowledge(c, proof) is False

    # a copied ciphertext cannot be re-randomized or modified with the same proof
    assert public_cs.verify_knowledge(public_cs.regenerate_ciphertext(c), proof, context="alice") is False
    if algorithm_name == "ElGamal":
        modified = c * public_cs.encrypt(2)
    else:
        modified = c + public_cs.encrypt(1)
    assert public_cs.verify_knowledge(modified, proof, context="alice") is False
    if algorithm_name != "ElGamal":
        assert public_cs.verify_knowledge(c * 3, proof, context="alice") is False

    # tampered and malformed proofs are rejected
    assert public_cs.verify_knowledge(c, tamper(proof), context="alice") is False
    assert public_cs.verify_knowledge(c, {}, context="alice") is False
    assert public_cs.verify_knowledge(c, None, context="alice") is False

    # a proof of another ciphertext does not prove this one
    other_c, other_proof = public_cs.encrypt_with_proof_of_knowledge(17, context="alice")
    assert public_cs.verify_knowledge(c, other_proof, context="alice") is False
    assert public_cs.verify_knowledge(other_c, other_proof, context="alice") is True

    logger.info(f"✅ Proof of knowledge test succeeded for {algorithm_name}")


def test_proof_of_knowledge_unsupported():
    for algorithm_name in ["ElGamal", "Exponential-ElGamal"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        with pytest.raises(ValueError, match="prime_order=True"):
            cs.encrypt_with_proof_of_knowledge(5)

    for algorithm_name in ["RSA", "Okamoto-Uchiyama"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
        with pytest.raises(ValueError, match="does not support proofs of knowledge"):
            cs.encrypt_with_proof_of_knowledge(5)
