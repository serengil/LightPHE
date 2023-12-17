import pytest
from typing import List
from lightphe.commons import phe_utils
from lightphe.models.Tensor import EncryptedTensor, Fraction
from lightphe import LightPHE

from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_tensors.py")

THRESHOLD = 0.5


def test_tensor_operations():
    cs = LightPHE(algorithm_name="Paillier")

    tensor = [1.005, 2.05, 3.005, 4.005, -5.05, 6, 7.003005]

    encrypted_tensors = cs.encrypt(tensor)

    decrypted_tensors = cs.decrypt(encrypted_tensors)

    for i, decrypted_tensor in enumerate(decrypted_tensors):
        assert abs(tensor[i] - decrypted_tensor) <= THRESHOLD

    logger.info("✅ Tensor tests succeeded")


def test_homomorphic_multiplication():
    cs = LightPHE(algorithm_name="RSA")

    t1 = [1.005, 2.05, -3.5, 3.5, 4]
    t2 = [5, 6.2, 7.002, 7.002, 8.02]

    c1: EncryptedTensor = cs.encrypt(t1)
    c2: EncryptedTensor = cs.encrypt(t2)

    c3 = c1 * c2

    restored_tensors = cs.decrypt(c3)

    for i, restored_tensor in enumerate(restored_tensors):
        assert abs((t1[i] * t2[i]) - restored_tensor) < THRESHOLD

    with pytest.raises(ValueError):
        _ = c1 + c2

    logger.info("✅ Homomorphic multiplication tests succeeded")


def test_homomorphic_addition():
    cs = LightPHE(algorithm_name="Paillier", key_size=30)

    t1 = [1.005, 2.05, -3.5, 4]
    t2 = [5, 6.2, 7.002, 8.02]

    c1: EncryptedTensor = cs.encrypt(t1)
    c2: EncryptedTensor = cs.encrypt(t2)

    c3 = c1 + c2

    restored_tensors = cs.decrypt(c3)

    for i, restored_tensor in enumerate(restored_tensors):
        assert abs((t1[i] + t2[i]) - restored_tensor) < THRESHOLD

    with pytest.raises(ValueError):
        _ = c1 * c2

    logger.info("✅ Homomorphic addition tests succeeded")
