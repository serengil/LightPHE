import pytest
from lightphe.cryptosystems.GoldwasserMicali import GoldwasserMicali
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_goldwasser.py")


def test_goldwasser():
    cs = GoldwasserMicali()

    security_level = cs.keys["public_key"]["n"].bit_length()

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
        cs.multiply_by_constant(c1, c2)

    logger.info(
        f"✅ Goldwasser-Micali test succeeded ({security_level} bit security level)"
    )


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Goldwasser-Micali")

    security_level = cs.cs.keys["public_key"]["n"].bit_length()

    # try different bit size messages
    ms = [(17, 21), (117, 23), (23, 117), (1117, 23), (12, 1118)]

    for m1, m2 in ms:
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

        logger.info(
            f"✅ Goldwasser-Micali api test succeeded for {m1.bit_length()}&{m2.bit_length()} bit plaintexts "
            f"({security_level} bit security level)"
        )
