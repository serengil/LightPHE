import os
from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_goldwasser.py")


# pylint: disable=eval-used
def test_private_available_after_export():
    target_file = "my_public_key.lphe"
    cs = LightPHE(algorithm_name="RSA")
    # we are dropping private key while exporting public key
    cs.export_keys(public=True, target_file=target_file)
    assert cs.cs.keys.get("private_key") is not None
    logger.info("✅ private key is not available in public key file as expected")

    with open(target_file, "r", encoding="UTF-8") as file:
        key_str = file.read()
        keys = eval(key_str)
        assert keys.get("private_key") is None
        logger.info(
            "✅ private key is available in cryptosystem's keys after"
            "its public key exported as expected"
        )

    os.remove(target_file)
