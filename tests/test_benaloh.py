import pytest
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_benaloh.py")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Benaloh", key_size=50)

    n = cs.cs.keys["public_key"]["n"]
    r = cs.cs.keys["public_key"]["r"]
    security_level = n.bit_length()

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert m1 * m2 < r, "Plain multiplication result exceeds plaintext modulo"
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info(f"✅ Benaloh api test succeeded ({security_level}-bit security level)")
