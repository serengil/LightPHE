import random
import time

import pytest
from lightecc import LightECC

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_camenischshoup.py")

cs = LightPHE(algorithm_name="Camenisch-Shoup", key_size=50)


@pytest.fixture(scope="module")
def large_cs():
    # verifiable encryption of secp256k1 secrets requires keys larger than 467 bits
    return LightPHE(algorithm_name="Camenisch-Shoup", key_size=1024)


def test_api():
    tic = time.time()
    modulo = cs.cs.plaintext_modulo

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    # negative plaintexts and addition wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
    assert cs.decrypt(cs.encrypt(plaintext=modulo - 1) + c1) == m1 - 1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    logger.info(f"✅ Camenisch-Shoup api test succeeded in {time.time() - tic:.2f} seconds")


def test_keys_are_well_formed():
    public_key = cs.cs.keys["public_key"]
    private_key = cs.cs.keys["private_key"]
    n = public_key["n"]
    n_square = n * n

    for i in [1, 2, 3]:
        assert public_key[f"y{i}"] == pow(public_key["g"], private_key[f"x{i}"], n_square)

    # g is a 2n-th power, so it vanishes when raised to 2n-th root of unity order
    assert public_key["g"] != 1
    assert public_key["h_bar"] != 1 and public_key["g_bar"] != 1
    assert public_key["n_bar"] != n


def test_labeled_encryption():
    for m in [0, 1, 17, cs.cs.plaintext_modulo - 1]:
        ciphertext = cs.cs.encrypt_with_label(plaintext=m, label="some label")
        assert cs.cs.decrypt_with_label(ciphertext=ciphertext, label="some label") == m

        # different label
        with pytest.raises(ValueError, match="different label"):
            cs.cs.decrypt_with_label(ciphertext=ciphertext, label="other label")

        # modified ciphertext
        u, e, v = ciphertext
        n_square = cs.cs.ciphertext_modulo
        for modified in [(u, e * (1 + cs.cs.plaintext_modulo) % n_square, v), (u, e, v + 1)]:
            with pytest.raises(ValueError, match="invalid"):
                cs.cs.decrypt_with_label(ciphertext=modified, label="some label")

        # labeled ciphertexts cannot be decrypted without label
        with pytest.raises(ValueError, match="labels"):
            cs.cs.decrypt(ciphertext)

        # homomorphic operations drop the validity tag
        c = cs.create_ciphertext_obj(ciphertext) + cs.encrypt(plaintext=3)
        assert len(c.value) == 2
        assert cs.decrypt(c) == (m + 3) % cs.cs.plaintext_modulo


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Camenisch-Shoup", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Camenisch-Shoup predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    public_cs = LightPHE(algorithm_name="Camenisch-Shoup", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * 2
    assert cs.decrypt(c) == 84

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_verifiable_encryption(large_cs):
    tic = time.time()
    ecc = LightECC()
    secret = random.randint(1, ecc.n - 1)
    public_point = ecc.G * secret
    label = "release if alice loses access"

    verifiable_ciphertext = large_cs.encrypt_verifiably(secret=secret, label=label)

    # public point is accepted both as a point and as coordinates
    assert large_cs.verify_encryption(verifiable_ciphertext, public_point, label=label) is True
    assert (
        large_cs.verify_encryption(verifiable_ciphertext, public_point.get_point(), label=label)
        is True
    )
    assert large_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext, label=label) == secret

    # wrong label or wrong public point
    assert large_cs.verify_encryption(verifiable_ciphertext, public_point, label="other") is False
    assert large_cs.verify_encryption(verifiable_ciphertext, ecc.G * (secret + 1), label=label) is False
    with pytest.raises(ValueError, match="different label"):
        large_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext, label="other")

    logger.info(
        f"✅ Camenisch-Shoup verifiable encryption test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_verifiable_encryption_rejects_tampering(large_cs):
    ecc = LightECC()
    secret = random.randint(1, ecc.n - 1)
    public_point = ecc.G * secret
    verifiable_ciphertext = large_cs.encrypt_verifiably(secret=secret)
    assert large_cs.verify_encryption(verifiable_ciphertext, public_point) is True

    # modify each part of the ciphertext, commitment and proof
    for index in range(3):
        tampered = dict(verifiable_ciphertext)
        ciphertext = list(verifiable_ciphertext["ciphertext"])
        ciphertext[index] += 1
        tampered["ciphertext"] = tuple(ciphertext)
        assert large_cs.verify_encryption(tampered, public_point) is False

    tampered = dict(verifiable_ciphertext)
    tampered["commitment"] += 1
    assert large_cs.verify_encryption(tampered, public_point) is False

    for field in ["challenge", "r", "s", "m"]:
        tampered = dict(verifiable_ciphertext)
        tampered["proof"] = dict(verifiable_ciphertext["proof"])
        tampered["proof"][field] += 1
        assert large_cs.verify_encryption(tampered, public_point) is False

    # ciphertext of another secret with the proof of this secret
    other = large_cs.encrypt_verifiably(secret=secret + 1)
    swapped = dict(verifiable_ciphertext)
    swapped["ciphertext"] = other["ciphertext"]
    assert large_cs.verify_encryption(swapped, public_point) is False

    # proof of another secret for this public point
    assert large_cs.verify_encryption(other, public_point) is False

    # malformed inputs
    for malformed in [{}, {"ciphertext": (1, 2)}, {**verifiable_ciphertext, "proof": None}]:
        assert large_cs.verify_encryption(malformed, public_point) is False


def test_verifiable_encryption_secret_range(large_cs):
    ecc = LightECC()
    for secret in [1, 2, ecc.n - 1]:
        verifiable_ciphertext = large_cs.encrypt_verifiably(secret=secret)
        assert large_cs.verify_encryption(verifiable_ciphertext, ecc.G * secret) is True
        assert large_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext) == secret

    # secrets are reduced to the order of the curve
    for secret in [ecc.n + 5, -5]:
        verifiable_ciphertext = large_cs.encrypt_verifiably(secret=secret)
        assert large_cs.verify_encryption(verifiable_ciphertext, ecc.G * (secret % ecc.n))
        assert large_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext) == secret % ecc.n

    # public point would be the point at infinity
    for secret in [0, ecc.n]:
        with pytest.raises(ValueError, match="multiple of the order"):
            large_cs.encrypt_verifiably(secret=secret)
    verifiable_ciphertext = large_cs.encrypt_verifiably(secret=1)
    assert large_cs.verify_encryption(verifiable_ciphertext, ecc.O) is False


def test_verifiable_encryption_other_curve(large_cs):
    edwards_cs = LightPHE(
        algorithm_name="Camenisch-Shoup",
        keys=large_cs.cs.keys,
        form="edwards",
        curve="ed25519",
    )
    ecc = LightECC(form_name="edwards", curve_name="ed25519")
    secret = random.randint(1, ecc.n - 1)

    verifiable_ciphertext = edwards_cs.encrypt_verifiably(secret=secret)
    assert edwards_cs.verify_encryption(verifiable_ciphertext, ecc.G * secret) is True
    assert edwards_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext) == secret


def test_verifiable_encryption_with_public_key_only(large_cs, tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    large_cs.export_keys(target_file=public_key_file, public=True)
    public_cs = LightPHE(algorithm_name="Camenisch-Shoup", key_file=public_key_file)

    ecc = LightECC()
    secret = random.randint(1, ecc.n - 1)

    # prover and verifier need the public key only
    verifiable_ciphertext = public_cs.encrypt_verifiably(secret=secret)
    assert public_cs.verify_encryption(verifiable_ciphertext, ecc.G * secret) is True

    with pytest.raises(ValueError, match="You must have private key"):
        public_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext)

    assert large_cs.decrypt_verifiable_ciphertext(verifiable_ciphertext) == secret


def test_verifiable_encryption_small_key():
    with pytest.raises(ValueError, match="too small for verifiable encryption"):
        cs.encrypt_verifiably(secret=5)

    with pytest.raises(ValueError, match="too small for verifiable encryption"):
        cs.verify_encryption({}, LightECC().G * 5)


@pytest.mark.parametrize("algorithm_name", ["Paillier", "Bresson-Catalano-Pointcheval"])
def test_verifiable_encryption_unsupported_algorithms(algorithm_name):
    other_cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
    point = LightECC().G * 5

    with pytest.raises(ValueError, match="does not support verifiable encryption"):
        other_cs.encrypt_verifiably(secret=5)

    with pytest.raises(ValueError, match="does not support verifiable encryption"):
        other_cs.verify_encryption({}, point)

    with pytest.raises(ValueError, match="does not support verifiable encryption"):
        other_cs.decrypt_verifiable_ciphertext({})


def test_large_keys(large_cs):
    tic = time.time()
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == m1 * 1000

    # floats and tensors
    c3 = large_cs.encrypt(plaintext=1.5)
    assert large_cs.decrypt(c3 * 4) == 6
    enc_tensor = large_cs.encrypt([1.5, 2.25, 3.5], silent=True)
    assert large_cs.decrypt(enc_tensor) == [1.5, 2.25, 3.5]
    assert large_cs.decrypt(enc_tensor @ [2, 4, 1]) == [15.5]

    logger.info(
        f"✅ Camenisch-Shoup 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_readme_verifiable_encryption(large_cs, tmp_path):
    public_key_file = str(tmp_path / "public.txt")

    # trusted third party builds the cryptosystem and publishes its public key
    ttp_cs = large_cs
    ttp_cs.export_keys(target_file=public_key_file, public=True)

    # alice's wallet key pair on secp256k1
    ecc = LightECC(curve_name="secp256k1")
    private_key = 123456789
    public_key = ecc.G * private_key

    # alice encrypts her private key for the trusted third party with a proof
    label = "release only if alice loses access to her wallet"
    alice_cs = LightPHE(algorithm_name="Camenisch-Shoup", key_file=public_key_file)
    escrow = alice_cs.encrypt_verifiably(secret=private_key, label=label)

    # bank verifies it with public keys only, without learning alice's private key
    bank_cs = LightPHE(algorithm_name="Camenisch-Shoup", key_file=public_key_file)
    assert bank_cs.verify_encryption(escrow, public_point=public_key, label=label) is True

    # trusted third party recovers the private key under the same label only
    assert ttp_cs.decrypt_verifiable_ciphertext(escrow, label=label) == private_key
