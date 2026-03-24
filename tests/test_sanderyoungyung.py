import time
from typing import Optional

import pytest

from lightphe.commons.logger import Logger

logger = Logger(module="tests/tets_sanderyoungyung.py")


def test_api_with_no_plaintext_limit():
    run_api()


def test_api_with_plaintext_limit():
    run_api(plaintext_limit=200)


def run_api(plaintext_limit: Optional[int] = None):
    tic = time.time()
    from lightphe import LightPHE

    cs = LightPHE(
        algorithm_name="Sander-Young-Yung",
        key_size=1024,
        plaintext_limit=plaintext_limit,
    )

    modulo = cs.cs.plaintext_modulo

    security_level = cs.cs.keys["public_key"]["n"].bit_length()

    # try different bit size messages
    ms = [(17, 22), (117, 23), (23, 117)]

    for m1, m2 in ms:
        c1 = cs.encrypt(plaintext=m1)
        c2 = cs.encrypt(plaintext=m2)

        # proof of decryption
        assert cs.decrypt(c1) == m1 % modulo
        assert cs.decrypt(c2) == m2 % modulo

        # re-randomization
        c1_prime = cs.cs.reencrypt(c1.value)
        c2_prime = cs.cs.reencrypt(c2.value)
        assert c1.value != c1_prime
        assert c2.value != c2_prime
        assert cs.cs.decrypt(c1_prime) == m1 % modulo
        assert cs.cs.decrypt(c2_prime) == m2 % modulo

        # homomorphic bitwise AND
        assert cs.decrypt(c1 & c2) == (m1 % modulo) & (m2 % modulo)

        # unsupported homomorphic operations
        with pytest.raises(ValueError):
            _ = c1 * c2

        with pytest.raises(ValueError):
            _ = c1 + c2

        with pytest.raises(ValueError):
            _ = c1 * 5

        with pytest.raises(ValueError):
            _ = 5 * c1
    toc = time.time()
    logger.info(
        f"✅ Sander-Young-Yung test ({plaintext_limit=}) succeeded ({security_level} bit"
        f" security level) in {toc - tic:.2f} seconds"
    )
