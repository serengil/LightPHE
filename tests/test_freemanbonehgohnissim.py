import random
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_freemanbonehgohnissim.py")

cs = LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_size=64)


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

    # homomorphic multiplication
    assert cs.decrypt(c1 * c2) == m1 * m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    # negative plaintexts
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
    assert cs.decrypt(c1 * c3) == modulo - 5 * m1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    logger.info(
        f"✅ Freeman-Boneh-Goh-Nissim api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_keys_are_well_formed():
    public_key = cs.cs.keys["public_key"]
    p, r = public_key["p"], public_key["r"]
    v = cs.cs.keys["private_key"]["v"]
    ec = cs.cs.ec

    # p + 1 points on y^2 = x^3 + x, and the generator has prime order r
    assert p % 4 == 3 and (p + 1) % r == 0
    assert (ec.G * (r - 1) + ec.G).get_point() == ec.O.get_point()

    # projection v vanishes on h1 and h2, but not on g
    def project(points):
        result = ec.O
        for point, scalar in zip(cs.cs._FreemanBonehGohNissim__points(points), v):
            result = result + cs.cs._FreemanBonehGohNissim__scale(point, scalar)
        return result.get_point()

    assert project(public_key["h1"]) == ec.O.get_point()
    assert project(public_key["h2"]) == ec.O.get_point()
    assert project(public_key["g"]) != ec.O.get_point()


def test_degree_2_functions():
    modulo = cs.cs.plaintext_modulo
    for _ in range(20):
        x, y, z = [random.randint(-100, 100) for _ in range(3)]
        k = random.randint(-20, 20)
        cx, cy, cz = cs.encrypt(x), cs.encrypt(y), cs.encrypt(z)

        assert cs.decrypt(cx * cx) == (x * x) % modulo
        assert cs.decrypt((cx + cy) * cz) == ((x + y) * z) % modulo

        # multiplied ciphertexts can be added with each other and with fresh ciphertexts
        assert cs.decrypt(cx * cy + cz * cz) == (x * y + z * z) % modulo
        assert cs.decrypt(cx * cy + cz) == (x * y + z) % modulo
        assert cs.decrypt(cz + cx * cy) == (z + x * y) % modulo

        # constants before and after multiplication, including zero
        assert cs.decrypt((cx * k) * cy) == (k * x * y) % modulo
        assert cs.decrypt(cx * cy * k) == (k * x * y) % modulo
        assert cs.decrypt(cx * 0) == 0


def test_only_one_multiplication():
    c1, c2, c3 = cs.encrypt(2), cs.encrypt(3), cs.encrypt(4)
    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * c2 * c3

    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * (c2 * c3)

    with pytest.raises(ValueError, match="non-multiplied ciphertexts only"):
        cs.regenerate_ciphertext(c1 * c2)


def test_plaintext_limit():
    assert cs.cs.keys["public_key"]["limit"] == 2**20

    small_cs = LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_size=64, plaintext_limit=100)
    assert small_cs.decrypt(small_cs.encrypt(100)) == 100
    assert small_cs.decrypt(small_cs.encrypt(-100)) == small_cs.cs.plaintext_modulo - 100
    assert small_cs.decrypt(small_cs.encrypt(10) * small_cs.encrypt(10)) == 100

    # results out of the limit cannot be restored
    with pytest.raises(ValueError, match="out of"):
        small_cs.decrypt(small_cs.encrypt(101))

    with pytest.raises(ValueError, match="out of"):
        small_cs.decrypt(small_cs.encrypt(11) * small_cs.encrypt(10))

    with pytest.raises(ValueError, match="too large"):
        LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_size=64, plaintext_limit=2**40)

    with pytest.raises(ValueError, match="too small"):
        LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_size=16)


def test_floats_and_tensors_are_not_supported():
    c = cs.encrypt(plaintext=5)
    for plaintext in [1.5, [1, 2, 3]]:
        with pytest.raises(ValueError, match="Freeman-Boneh-Goh-Nissim does not support float"):
            cs.encrypt(plaintext=plaintext)

    with pytest.raises(ValueError, match="Freeman-Boneh-Goh-Nissim does not support float"):
        _ = c * 1.5


def test_catalano_fiore_is_not_needed():
    with pytest.raises(ValueError, match="already supports one multiplication"):
        LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", keys=cs.cs.keys, boost="Catalano-Fiore")


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", keys=cs.cs.keys)
    c1 = cs.encrypt(plaintext=11)
    c2 = restored_cs.encrypt(plaintext=7)
    assert restored_cs.decrypt(c1 * c2) == 77
    assert cs.decrypt(c1 + c2) == 18
    logger.info("✅ Freeman-Boneh-Goh-Nissim predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    # multiplication requires the public key only
    public_cs = LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * public_cs.encrypt(plaintext=2) + public_cs.encrypt(1)
    assert cs.decrypt(c) == 85

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Freeman-Boneh-Goh-Nissim", key_size=1024)
    assert large_cs.cs.keys["public_key"]["r"].bit_length() == 256

    c1 = large_cs.encrypt(plaintext=123)
    c2 = large_cs.encrypt(plaintext=-456)
    assert large_cs.decrypt(c1 + c2) == large_cs.cs.plaintext_modulo - 333
    assert large_cs.decrypt(c1 * c2 + c1) == large_cs.cs.plaintext_modulo - 123 * 456 + 123

    logger.info(
        f"✅ Freeman-Boneh-Goh-Nissim 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )
