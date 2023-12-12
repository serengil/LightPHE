import pytest
from lightphe.cryptosystems.Paillier import Paillier
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_paillier.py")


def test_paillier():
    pai = Paillier()

    m1 = pai.plaintext_modulo + 654
    m2 = pai.plaintext_modulo + 123

    c1 = pai.encrypt(m1)
    c2 = pai.encrypt(m2)

    # homomorphic operations
    assert pai.decrypt(pai.add(c1, c2)) == (m1 + m2) % pai.plaintext_modulo
    assert pai.decrypt(pai.multiply_by_contant(c1, m2)) == (m1 * m2) % pai.plaintext_modulo

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        pai.multiply(c1, c2)

    with pytest.raises(ValueError):
        pai.xor(c1, c2)

    # re-encryption
    c1_prime = pai.reencrypt(c1)
    assert c1_prime != c1
    assert pai.decrypt(c1_prime) == m1 % pai.plaintext_modulo

    logger.info("✅ Paillier test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Paillier")

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

    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == cs.decrypt(c1)

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Paillier api test succeeded")


def test_float_operations():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Paillier")

    m1 = 1000
    m2 = -10

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    assert cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c2 + c1) == m1 + m2

    k1 = 20
    assert cs.decrypt(c1 * k1) == m1 * k1
    assert cs.decrypt(k1 * c1) == m1 * k1

    k2 = 1.05
    assert cs.decrypt(c1 * k2) == m1 * k2
    assert cs.decrypt(k2 * c1) == m1 * k2

    k3 = -20
    assert cs.decrypt(c1 * k3) == (m1 * k3) % cs.cs.plaintext_modulo
    assert cs.decrypt(k3 * c1) == (m1 * k3) % cs.cs.plaintext_modulo
