import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_bonehgodnissim.py")

cs = LightPHE(
    algorithm_name="Boneh-Goh-Nissim",
    key_size=50,
    max_tries=10000,
)
security_level = cs.cs.ec.n.bit_length()


def test_api():
    tic = time.time()

    m1 = 83
    m2 = 31

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == (m1 + m2) % cs.cs.plaintext_modulo

    # homomorphic multiplication (once)
    c1_times_c2 = c1 * c2
    assert cs.decrypt(c1_times_c2) == (m1 * m2) % cs.cs.plaintext_modulo

    # scalar multiplication
    k = 2
    assert cs.decrypt(c1 * k) == (m1 * k) % cs.cs.plaintext_modulo

    # unsupported homomorphic operations
    with pytest.raises(
        ValueError,
        match="Boneh-Goh-Nissim only supports multiplication ciphertexts once!",
    ):
        _ = c1_times_c2 * c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    # re-randomization
    c1_prime = cs.cs.reencrypt(c1.value)
    c2_prime = cs.cs.reencrypt(c2.value)
    # assert c1.value != c1_prime
    # assert c2.value != c2_prime
    assert cs.cs.decrypt(c1_prime) == m1
    assert cs.cs.decrypt(c2_prime) == m2

    logger.info(
        f"✅ Boneh-God-Nissim test succeeded ({security_level} bit ECC security level)"
        f" in {time.time() - tic:.2f} seconds"
    )


def test_linear_regression():
    tic = time.time()

    x1 = 5
    w1 = 7

    x2 = 3
    w2 = 4

    x1_enc = cs.encrypt(plaintext=x1)
    w1_enc = cs.encrypt(plaintext=w1)

    x2_enc = cs.encrypt(plaintext=x2)
    w2_enc = cs.encrypt(plaintext=w2)

    x1w1_enc = x1_enc * w1_enc
    x2w2_enc = x2_enc * w2_enc

    sum_enc = x1w1_enc + x2w2_enc

    sum_decrypted = cs.decrypt(sum_enc)

    assert sum_decrypted == (x1 * w1 + x2 * w2)

    # multiplication by constant
    _5x1w1_enc = cs.decrypt(x1w1_enc * 5)
    assert _5x1w1_enc == (5 * x1 * w1)

    # unsupported homomorphic operations
    with pytest.raises(
        ValueError,
        match="Boneh-Goh-Nissim only supports multiplication ciphertexts once!",
    ):
        _ = x1w1_enc * w2_enc

    logger.info(
        f"✅ Boneh-God-Nissim linear regression test succeeded "
        f"({security_level} bit ECC security level)"
        f" in {time.time() - tic:.2f} seconds"
    )


def test_cosine_similarity():
    tic = time.time()
    i1 = 5
    i2 = 2
    i3 = 8

    # v2 = [1, 1, 2]
    j1 = 1
    j2 = 1
    j3 = 2

    i1_enc = cs.encrypt(i1)
    i2_enc = cs.encrypt(i2)
    i3_enc = cs.encrypt(i3)

    j1_enc = cs.encrypt(j1)
    j2_enc = cs.encrypt(j2)
    j3_enc = cs.encrypt(j3)

    # homomorphic operation
    cosine_sim_enc = i1_enc * j1_enc + i2_enc * j2_enc + i3_enc * j3_enc

    # proof of work
    assert cs.decrypt(cosine_sim_enc) == i1 * j1 + i2 * j2 + i3 * j3

    logger.info(
        f"✅ Boneh-God-Nissim cosine similarity test succeeded "
        f"({security_level} bit ECC security level)"
        f" in {time.time() - tic:.2f} seconds"
    )


def test_euclidean_distance():
    tic = time.time()

    # v1 = [5, 2, 3]
    i1 = 5
    i2 = 2
    i3 = 8

    # v2 = [1, 1, 2]
    j1 = 1
    j2 = 1
    j3 = 2

    i1_enc = cs.encrypt(i1)
    i2_enc = cs.encrypt(i2)
    i3_enc = cs.encrypt(i3)

    j1_enc = cs.encrypt(-j1)
    j2_enc = cs.encrypt(-j2)
    j3_enc = cs.encrypt(-j3)

    euclidean_sqrt_enc = (
        (i1_enc + j1_enc) * (i1_enc + j1_enc)
        + (i2_enc + j2_enc) * (i2_enc + j2_enc)
        + (i3_enc + j3_enc) * (i3_enc + j3_enc)
    )

    assert (
        cs.decrypt(euclidean_sqrt_enc)
        == (i1 - j1) ** 2 + (i2 - j2) ** 2 + (i3 - j3) ** 2
    )

    logger.info(
        f"✅ Boneh-God-Nissim euclidean distance test succeeded "
        f"({security_level} bit ECC security level)"
        f" in {time.time() - tic:.2f} seconds"
    )


def test_api_with_predefined_keys():
    keys = {
        "private_key": {"q1": 1260048562698661, "q2": 1495813357973021},
        "public_key": {
            "curve": {
                "a": 1,
                "b": 0,
                "p": 1477681217875020437035023206706703,
                "G": (
                    404050258967758769169929337984186,
                    548422986186523785500578682099939,
                ),
                "n": 1884797471779362802340590824881,
            },
            "G": (404050258967758769169929337984186, 548422986186523785500578682099939),
            "u": (
                496699107331579016081758964967239,
                1209427529257066171815901459972102,
            ),
            "h": (557434130026147587760748115479880, 109859910481881270030204038710204),
            "l": 784,
        },
    }

    bgn_cs = LightPHE(
        algorithm_name="Boneh-Goh-Nissim",
        keys=keys,
    )
    security_level = bgn_cs.cs.ec.n.bit_length()

    m1 = 3
    m2 = 2

    c1 = bgn_cs.encrypt(plaintext=m1)
    c2 = bgn_cs.encrypt(plaintext=m2)

    # proof of decryption
    assert bgn_cs.decrypt(c1) == m1
    assert bgn_cs.decrypt(c2) == m2

    # homomorphic addition
    assert bgn_cs.decrypt(c1 + c2) == (m1 + m2) % bgn_cs.cs.plaintext_modulo

    # homomorphic multiplication
    c1_times_c2 = c1 * c2
    assert bgn_cs.decrypt(c1_times_c2) == (m1 * m2) % bgn_cs.cs.plaintext_modulo

    # scalar multiplication
    k = 2
    assert bgn_cs.decrypt(c1 * k) == (m1 * k) % bgn_cs.cs.plaintext_modulo

    # unsupported homomorphic operations

    with pytest.raises(ValueError):
        _ = c1 & c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    # re-randomization
    c1_prime = bgn_cs.cs.reencrypt(c1.value)
    c2_prime = bgn_cs.cs.reencrypt(c2.value)
    # assert c1.value != c1_prime
    # assert c2.value != c2_prime
    assert bgn_cs.cs.decrypt(c1_prime) == m1
    assert bgn_cs.cs.decrypt(c2_prime) == m2

    logger.info(
        f"✅ Boneh-God-Nissim test succeeded ({security_level} bit ECC security level)"
    )
