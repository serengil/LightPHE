from typing import List
from lightphe.commons import phe_utils
from lightphe import LightPHE

from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_tensors.py")


def test_tensor_operations():
    cs = LightPHE(algorithm_name="Paillier", key_size=25)

    tensor = [1.005, 2.005, 3.005, -4.005, 5.005]

    encrypted_tensors = cs.encrypt(tensor)

    decrypted_tensors = cs.decrypt(encrypted_tensors)

    for i, decrypted_tensor in enumerate(decrypted_tensors):
        assert abs(tensor[i] - decrypted_tensor) <= 0.5

    logger.info("✅ Tensor tests succeeded")

    # TODO: add homomorphic operations on encrypted tensors
    # homomorphic multiplication and scalar multiplication are easy
    # but addition requires it to cast int
