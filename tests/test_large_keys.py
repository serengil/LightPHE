import time
import unittest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_large_keys.py")


@unittest.skip("This is an experimental test for large key sizes.")
def test_large_keys():
    """
    Use this test to see no problem for larger keys.

    Algorithm| Key Size | Key Generation Time | Encryption Time | Homomorphic Time | Decryption Time
    --- | --- | --- | --- | --- | ---
    Goldwasser-Micali | 1024 | 0.01 | 0.00 | 0.00 |0.00
    Goldwasser-Micali | 2048 | 0.08 | 0.00 | 0.00 |0.03
    Goldwasser-Micali | 3072 | 0.45 | 0.00 | 0.00 |0.08
    Goldwasser-Micali | 7680 | 11.30 | 0.00 | 0.00 |1.21

    Benaloh | 1024 | 4.91 | 0.00 | 0.00 |0.01
    Benaloh | 2048 | 140.54 | 0.00 | 0.00 |0.03
    Benaloh | 3072 | 439.46 | 0.00 | 0.00 |0.08

    Naccache-Stern | 1024 | 19.97 | 0.00 | 0.00 |0.06
    """
    algorithms = [
        "Naccache-Stern",
        "Goldwasser-Micali",
        "Benaloh",
    ]
    key_sizes = [1024, 2048, 3072, 7680]

    for key_size in key_sizes:
        for algorithm_name in algorithms:
            logger.debug(f"Testing {algorithm_name} with key size {key_size} bits")
            tic = time.time()
            cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size)
            toc = time.time()
            keygen_time = toc - tic

            m1 = 17
            m2 = 23

            tic = time.time()
            c1 = cs.encrypt(m1)
            c2 = cs.encrypt(m2)
            toc = time.time()
            encryption_time = toc - tic

            if algorithm_name in ["Naccache-Stern", "Benaloh"]:
                tic = time.time()
                c3 = c1 + c2
                toc = time.time()
                homomorphic_time = toc - tic

                tic = time.time()
                result = cs.decrypt(c3)
                toc = time.time()
                decryption_time = toc - tic
                assert result == m1 + m2
            elif algorithm_name in ["Goldwasser-Micali"]:
                tic = time.time()
                c3 = c1 ^ c2
                toc = time.time()
                homomorphic_time = toc - tic

                tic = time.time()
                result = cs.decrypt(c3)
                toc = time.time()
                decryption_time = toc - tic
                assert result == m1 ^ m2

            logger.info(
                f"{algorithm_name} | {key_size} | {keygen_time:.2f} | {encryption_time:.2f} | {homomorphic_time:.2f} |{decryption_time:.2f}"
            )
