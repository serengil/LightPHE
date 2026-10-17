import copy
import pickle
import random
import time

import pytest

from lightphe import LightPHE
from lightphe.models.CatalanoFiore import SUPPORTED_ALGORITHMS
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_catalanofiore.py")

# plain cryptosystem, and the one supporting multiplication with the same keys
cs = LightPHE(algorithm_name="Paillier", key_size=128)
cf = LightPHE(algorithm_name="Paillier", keys=cs.cs.keys, boost="Catalano-Fiore")


@pytest.mark.parametrize("algorithm_name", SUPPORTED_ALGORITHMS)
def test_degree_2_functions(algorithm_name):
    tic = time.time()
    transform = LightPHE(algorithm_name=algorithm_name, key_size=64, boost="Catalano-Fiore")
    modulo = transform.cs.plaintext_modulo

    for _ in range(5):
        x, y, z, k = [random.randint(0, modulo - 1) for _ in range(4)]
        cx, cy, cz = transform.encrypt(x), transform.encrypt(y), transform.encrypt(z)

        assert transform.decrypt(cx) == x
        assert transform.decrypt(cx + cy) == (x + y) % modulo
        assert transform.decrypt(cx * k) == (x * k) % modulo
        assert transform.decrypt(cx * cy) == (x * y) % modulo
        assert transform.decrypt(cx * cx) == (x * x) % modulo

        # x * y + k * z * x - y + 7
        result = cx * cy + k * (cz * cx) - cy + 7
        assert transform.decrypt(result) == (x * y + k * z * x - y + 7) % modulo

    logger.info(
        f"✅ Catalano-Fiore on {algorithm_name} succeeded in {time.time() - tic:.2f} seconds"
    )


def test_operations():
    modulo = cf.cs.plaintext_modulo
    c3, c4, c5 = cf.encrypt(3), cf.encrypt(4), cf.encrypt(5)

    # one multiplication, then additions and scalar multiplications
    assert cf.decrypt(c3 * c4 + c5) == 17
    assert cf.decrypt(c3 * c4 * 2 + c3 * c5) == 39
    assert cf.decrypt(2 * (c3 * c4)) == 24

    # plain constants
    assert cf.decrypt(c3 + 10) == 13
    assert cf.decrypt(10 + c3 * c4) == 22
    assert cf.decrypt(c3 * c4 - 2) == 10

    # subtraction, negation and wrapping around the plaintext modulo
    assert cf.decrypt(c3 - c4) == modulo - 1
    assert cf.decrypt(-c3) == modulo - 3
    assert cf.decrypt(c3 * c4 - c5 * c5) == modulo - 13
    assert cf.decrypt(20 - c3 * c4) == 8

    # sum starts from 0
    assert cf.decrypt(sum([c3 * c4, c5, c3])) == 20

    # negative and zero plaintexts, and multiplication with zero
    assert cf.decrypt(cf.encrypt(-6)) == modulo - 6
    assert cf.decrypt(cf.encrypt(-6) * c4) == modulo - 24
    assert cf.decrypt(cf.encrypt(0) * c4) == 0
    assert cf.decrypt(c3 * c4 * 0) == 0


def test_ciphertexts_are_randomized():
    c1, c2 = cf.encrypt(5), cf.encrypt(5)
    assert c1.a != c2.a
    assert c1.beta.value != c2.beta.value
    assert cf.decrypt(c1) == cf.decrypt(c2) == 5


def test_ciphertexts_do_not_carry_private_key():
    c = cf.encrypt(5) * cf.encrypt(6) + cf.encrypt(7)
    assert c.cf.cs.cs.keys.get("private_key") is None

    # ciphertexts can be sent to another party, and still be decrypted by the key owner
    restored = pickle.loads(pickle.dumps(c))
    assert restored.cf.cs.cs.keys.get("private_key") is None
    assert cf.decrypt(restored + cf.encrypt(1)) == 38


def test_dot_product_of_encrypted_vectors():
    xs = [random.randint(0, 1000) for _ in range(10)]
    ys = [random.randint(0, 1000) for _ in range(10)]
    encrypted_xs = [cf.encrypt(x) for x in xs]
    encrypted_ys = [cf.encrypt(y) for y in ys]

    result = sum(ex * ey for ex, ey in zip(encrypted_xs, encrypted_ys))
    assert cf.decrypt(result) == sum(x * y for x, y in zip(xs, ys))

    # a pair of ciphertexts is kept for every product
    assert len(result.pairs) == 10


def test_only_one_multiplication():
    c1, c2, c3 = cf.encrypt(2), cf.encrypt(3), cf.encrypt(4)
    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * c2 * c3

    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * (c2 * c3)


def test_public_key_only(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    # server encrypts and evaluates with the public key only
    server_cf = LightPHE(
        algorithm_name="Paillier", key_file=public_key_file, boost="Catalano-Fiore"
    )
    c1 = cf.encrypt(6)
    c2 = server_cf.encrypt(7)
    result = c1 * c2 + server_cf.encrypt(8)

    with pytest.raises(ValueError, match="You must have private key"):
        server_cf.decrypt(result)

    assert cf.decrypt(result) == 50


def test_invalid_inputs():
    c = cf.encrypt(5)

    for plaintext in [1.5, [1, 2], "5", True]:
        with pytest.raises(ValueError, match="integers only"):
            cf.encrypt(plaintext)

    with pytest.raises(ValueError, match="multiplied with a ciphertext or an integer"):
        _ = c * 1.5

    with pytest.raises(ValueError, match="added to a ciphertext or an integer"):
        _ = c + 1.5

    with pytest.raises(ValueError, match="cannot be regenerated"):
        cf.regenerate_ciphertext(c)

    other_cf = LightPHE(algorithm_name="Paillier", key_size=128, boost="Catalano-Fiore")
    with pytest.raises(ValueError, match="different cryptosystems"):
        _ = c + other_cf.encrypt(1)


@pytest.mark.parametrize(
    "algorithm_name,reason",
    [
        ("Exponential-ElGamal", "discrete logarithm"),
        ("EllipticCurve-ElGamal", "discrete logarithm"),
        ("Okamoto-Uchiyama", "plaintext modulus p is secret"),
        ("Regev", "noise budget"),
        ("Goldwasser-Micali", "xor only"),
        ("Boneh-Goh-Nissim", "already supports one multiplication"),
        ("RSA", "not additively homomorphic"),
        ("ElGamal", "not additively homomorphic"),
    ],
)
def test_unsupported_algorithms(algorithm_name, reason):
    key_size = 64 if algorithm_name != "Regev" else 16
    with pytest.raises(ValueError, match=f"does not support {algorithm_name} because .*{reason}"):
        LightPHE(algorithm_name=algorithm_name, key_size=key_size, boost="Catalano-Fiore")


def test_unknown_boost():
    with pytest.raises(ValueError, match="Unknown boost"):
        LightPHE(algorithm_name="Paillier", key_size=64, boost="something")


def test_default_behaviour_is_unchanged():
    # no boost by default, so ciphertexts are regular ones
    keys = copy.deepcopy(cs.cs.keys)
    c1 = cs.encrypt(5)
    _ = cf.encrypt(5) * cf.encrypt(6)
    assert cs.cs.keys == keys
    assert cs.decrypt(c1 + cs.encrypt(3)) == 8
    assert cs.decrypt(cs.encrypt(1.5) * 2) == 3
    with pytest.raises(ValueError):
        _ = c1 * cs.encrypt(3)

    # each one decrypts ciphertexts of the other, as they have the same keys
    assert cf.decrypt(c1) == 5
    assert cs.decrypt(cf.encrypt(5) * cf.encrypt(6)) == 30


def test_large_keys():
    tic = time.time()
    large_cf = LightPHE(algorithm_name="Paillier", key_size=1024, boost="Catalano-Fiore")
    x = random.getrandbits(400)
    y = random.getrandbits(400)
    assert large_cf.decrypt(large_cf.encrypt(x) * large_cf.encrypt(y)) == x * y
    logger.info(f"✅ Catalano-Fiore 1024-bit key test succeeded in {time.time() - tic:.2f} seconds")


def test_readme_example():
    # client builds a cryptosystem supporting multiplication, and encrypts its private vectors
    client_cs = LightPHE(algorithm_name="Paillier", key_size=256, boost="Catalano-Fiore")

    x = [3, 1, 4]
    y = [1, 5, 9]
    encrypted_x = [client_cs.encrypt(value) for value in x]
    encrypted_y = [client_cs.encrypt(value) for value in y]

    # server computes dot product of encrypted vectors, ciphertexts carry the public key only
    encrypted_dot = sum(ex * ey for ex, ey in zip(encrypted_x, encrypted_y))

    # squared euclidean distance is also a degree-2 function
    encrypted_distance = sum((ex - ey) * (ex - ey) for ex, ey in zip(encrypted_x, encrypted_y))

    # client decrypts the results
    assert client_cs.decrypt(encrypted_dot) == 44
    assert client_cs.decrypt(encrypted_distance) == 45

    # multiplying again is not supported
    with pytest.raises(ValueError, match="only one multiplication"):
        _ = encrypted_dot * encrypted_x[0]
