import pytest

from lightphe.cryptosystems.RSA import RSA
from lightphe.commons.logger import Logger

logger = Logger()


def test_rsa():
    rsa = RSA()

    m1 = rsa.modulo + 9
    m2 = rsa.modulo + 11

    c1 = rsa.encrypt(m1)
    c2 = rsa.encrypt(m2)
    c3 = rsa.multiply(c1, c2)

    # homomorphic operations
    assert rsa.decrypt(c3) == (m1 * m2) % rsa.modulo

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        rsa.add(c1, c2)

    with pytest.raises(ValueError):
        rsa.xor(c1, c2)

    with pytest.raises(ValueError):
        rsa.multiply_by_contant(c1, c2)

    with pytest.raises(ValueError):
        rsa.reencrypt(c1)

    logger.info("✅ RSA test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="RSA")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 + c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 * 5

    with pytest.raises(ValueError):
        _ = 5 * c1

    logger.info("✅ RSA api test succeeded")
