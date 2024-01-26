import pytest
from lightphe.commons.logger import Logger
from lightphe import LightPHE

logger = Logger(module="tests/test_cloud.py")

# pre-generated 20-bit RSA keys
PRIVATE = {"private_key": {"d": 30365}, "public_key": {"n": 175501, "e": 101753}}
PUBLIC = {"public_key": {"n": 175501, "e": 101753}}


def test_encryption():
    # i actually have both private and public key
    # but one can encrypt messages with public key only
    cs = LightPHE(algorithm_name="RSA", keys=PUBLIC)
    secret_cs = LightPHE(algorithm_name="RSA", keys=PRIVATE)

    # plaintexts
    m1 = 10000
    c1 = cs.encrypt(m1)

    m2 = 1.05
    c2 = cs.encrypt(m2)

    assert secret_cs.decrypt(c1) == m1
    logger.info("✅ Cloud encryption tests done")

    c3_val = homomorphic_operations(c1=c1.value, c2=c2.value)
    c3 = cs.create_ciphertext_obj(c3_val)

    assert secret_cs.decrypt(c3) == m1 * m2
    logger.info("✅ Cloud decryption tests done")


def homomorphic_operations(c1: int, c2: int):
    """
    One can perform homomorphic operations while he/she does not hold the private key
    """
    cs = LightPHE(algorithm_name="RSA", keys=PUBLIC)
    c1_obj = cs.create_ciphertext_obj(c1)
    c2_obj = cs.create_ciphertext_obj(c2)

    # one cannot perform decryoption without private key
    with pytest.raises(ValueError):
        cs.decrypt(c1_obj)

    with pytest.raises(ValueError):
        cs.decrypt(c2_obj)

    # no need private key!
    c3 = c1_obj * c2_obj
    logger.info("✅ Cloud homomorphic operation tests done")
    return c3.value
