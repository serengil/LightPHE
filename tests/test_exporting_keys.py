import os
import json
import pytest
from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_exporting_keys.py")


def test_private_available_after_export():
    target_file = "my_public_key.lphe"
    cs = LightPHE(algorithm_name="RSA", key_size=50)
    # we are dropping private key while exporting public key
    cs.export_keys(public=True, target_file=target_file)
    assert cs.cs.keys.get("private_key") is not None
    logger.info("✅ private key is not available in public key file as expected")

    with open(target_file, "r", encoding="UTF-8") as file:
        key_str = file.read()
        keys = json.loads(key_str)
        assert keys.get("private_key") is None
        logger.info(
            "✅ private key is available in cryptosystem's keys after"
            "its public key exported as expected"
        )

    os.remove(target_file)


def test_malicious_key_file_is_not_executed(tmp_path):
    marker_file = tmp_path / "pwned.txt"
    key_file = tmp_path / "malicious.lphe"
    payload = f"__import__('pathlib').Path({str(marker_file)!r}).write_text('pwned')"
    key_file.write_text(payload, encoding="UTF-8")

    with pytest.raises(ValueError):
        LightPHE(algorithm_name="RSA", key_file=str(key_file))

    assert not marker_file.exists()
    logger.info("✅ key file content is not executed while restoring keys")
