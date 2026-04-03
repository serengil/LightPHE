# 3rd party dependencies
from lightphe import LightPHE

# project dependencies
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ciphertexts.py")

onprem_cs = LightPHE(algorithm_name="Paillier", key_size=50)


def test_private_key_not_available_in_ciphertext():
    m = 17

    c = onprem_cs.encrypt(m)

    assert c.cs.keys.get("private_key") is None
    assert onprem_cs.cs.keys.get("private_key") is not None

    logger.info("✅ Private key not available in ciphertext tests done")


def test_private_key_not_available_in_encrypted_tensor():
    t = [1.5, 2.4, 3.3, 4.2, 5.1]

    c = onprem_cs.encrypt(t, silent=True)

    assert c.cs.keys.get("private_key") is None
    assert onprem_cs.cs.keys.get("private_key") is not None

    logger.info("✅ Private key not available in encrypted tensor tests done")
