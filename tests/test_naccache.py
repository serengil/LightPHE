import pytest
from lightphe.cryptosystems.NaccacheStern import NaccacheStern
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_naccache.py")


def test_naccache_on_plaintexts():
    cs = NaccacheStern(key_size=37, deterministic=False)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    assert cs.decrypt(c1) == m1 % cs.plaintext_modulo
    assert cs.decrypt(c2) == m2 % cs.plaintext_modulo

    # homomorphic operations
    assert cs.decrypt(cs.add(c1, c2)) == (m1 + m2) % cs.plaintext_modulo
    assert cs.decrypt(cs.multiply_by_contant(c2, m1)) == (m1 * m2) % cs.plaintext_modulo

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    # re-encryption
    c1_prime = cs.reencrypt(c1)
    assert c1_prime != c1
    assert cs.decrypt(c1_prime) == m1 % cs.plaintext_modulo
    logger.info("✅ Probabilistic Naccache-Stern test succeeded")


def test_deterministic_version():
    cs = NaccacheStern(deterministic=True)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    assert cs.decrypt(c1) == m1 % cs.plaintext_modulo
    assert cs.decrypt(c2) == m2 % cs.plaintext_modulo

    # homomorphic operations
    assert cs.decrypt(cs.add(c1, c2)) == (m1 + m2) % cs.plaintext_modulo
    assert cs.decrypt(cs.multiply_by_contant(c2, m1)) == (m1 * m2) % cs.plaintext_modulo

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    with pytest.raises(ValueError):
        cs.reencrypt(c1)

    logger.info("✅ Deterministic Naccache-Stern test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Naccache-Stern")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Naccache-Stern api test succeeded")
