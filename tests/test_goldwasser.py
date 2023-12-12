import pytest
from lightphe.cryptosystems.GoldwasserMicali import GoldwasserMicali
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_goldwasser.py")


def test_goldwasser():
    cs = GoldwasserMicali()

    m1 = 17
    m2 = 27

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    # encryption & decryption tests
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic operations
    assert cs.decrypt(cs.xor(c1, c2)) == m1 ^ m2

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.add(c1, c2)

    with pytest.raises(ValueError):
        cs.multiply_by_contant(c1, c2)

    logger.info("✅ Goldwasser-Micali test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Goldwasser-Micali")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 ^ c2) == m1 ^ m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 + c2

    with pytest.raises(ValueError):
        _ = c1 * 5

    with pytest.raises(ValueError):
        _ = 5 * c1

    logger.info("✅ Goldwasser-Micali api test succeeded")
