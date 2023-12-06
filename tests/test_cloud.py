from lightphe.commons.logger import Logger
from lightphe import LightPHE

logger = Logger()

# pre-generated 20-bit RSA keys
PRIVATE = {"private_key": {"d": 30365}, "public_key": {"n": 175501, "e": 101753}}
PUBLIC = {"public_key": {"n": 175501, "e": 101753}}


def test_encryption():
    cs = LightPHE(algorithm_name="RSA", keys=PRIVATE)

    # plaintexts
    m1 = 10000
    c1 = cs.encrypt(m1)

    # m2 = 1.05 # TODO: add support
    m2 = 5
    c2 = cs.encrypt(m2)

    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    logger.info("✅ Cloud encryption tests done")

    c3_val = homomorphic_operations(c1.value, c2.value)
    c3 = cs.create_ciphertext_obj(c3_val)

    assert cs.decrypt(c3) == m1 * m2

    logger.info("✅ Cloud decryption tests done")


def homomorphic_operations(c1: int, c2: int):
    """
    One can perform homomorphic operations while he/she does not hold the private key
    """
    cs = LightPHE(algorithm_name="RSA", keys=PUBLIC)
    c1_obj = cs.create_ciphertext_obj(c1)
    c2_obj = cs.create_ciphertext_obj(c2)
    c3 = c1_obj * c2_obj
    logger.info("✅ Cloud homomorphic operation tests done")
    return c3.value
