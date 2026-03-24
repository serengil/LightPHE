import time

import pytest

from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_bonehgodnissim.py")


def test_api():
    from lightphe import LightPHE

    tic = time.time()

    # i run successful experiments with 100 bit key size, but it sometimes fails
    # try 50 bit for unit tests
    cs = LightPHE(
        algorithm_name="Boneh-Goh-Nissim",
        key_size=1024,
        max_tries=10000,
    )
    security_level = cs.cs.ec.n.bit_length()

    m1 = 83
    m2 = 31

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == (m1 + m2) % cs.cs.plaintext_modulo

    # homomorphic multiplication
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
        c1_times_c2_sq = c1_times_c2 * c2

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


def test_api_with_predefined_keys():
    from lightphe import LightPHE

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

    cs = LightPHE(
        algorithm_name="Boneh-Goh-Nissim",
        keys=keys,
    )
    security_level = cs.cs.ec.n.bit_length()

    m1 = 3
    m2 = 2

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == (m1 + m2) % cs.cs.plaintext_modulo

    # homomorphic multiplication
    c1_times_c2 = c1 * c2
    assert cs.decrypt(c1_times_c2) == (m1 * m2) % cs.cs.plaintext_modulo

    # scalar multiplication
    k = 2
    assert cs.decrypt(c1 * k) == (m1 * k) % cs.cs.plaintext_modulo

    # unsupported homomorphic operations

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
    )
