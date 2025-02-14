# built-in dependencies
from typing import List
import random

# 3rd party dependencies
import pytest

# project dependencies
from lightphe.commons import phe_utils
from lightphe.models.Tensor import EncryptedTensor
from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_tensors.py")

THRESHOLD = 1


# pylint: disable=consider-using-enumerate
def convert_negative_float_to_int(value: float, modulo: int) -> float:
    x, y = phe_utils.fractionize(
        value=value % modulo,
        modulo=modulo,
        precision=5,
    )
    return int(x / y)


def test_tensor_encryption():
    cs = LightPHE(algorithm_name="Paillier")

    tensor = [1.005, 2.05, 3.005, 4.005, -5.05, 6, 7.003005, -3.5 * 7.002]

    encrypted_tensors = cs.encrypt(tensor)

    decrypted_tensors = cs.decrypt(encrypted_tensors)

    for i, decrypted_tensor in enumerate(decrypted_tensors):
        expected_tensor = tensor[i]
        assert abs(expected_tensor - decrypted_tensor) <= THRESHOLD

    logger.info("✅ Tensor tests succeeded")


def test_homomorphic_multiplication():
    cs = LightPHE(algorithm_name="RSA")

    t1 = [1.005, 2.05, -3.5, 3.1, -4]
    t2 = [5, 6.2, -7.002, -7.1, 8.02]

    c1: EncryptedTensor = cs.encrypt(t1)
    c2: EncryptedTensor = cs.encrypt(t2)

    c3 = c1 * c2

    restored_tensors = cs.decrypt(c3)

    for i, restored_tensor in enumerate(restored_tensors):
        assert abs((t1[i] * t2[i]) - restored_tensor) < THRESHOLD

    with pytest.raises(ValueError):
        _ = c1 + c2

    with pytest.raises(ValueError):
        _ = c2 * 2

    logger.info("✅ Homomorphic multiplication tests succeeded")


def test_homomorphic_multiply_by_a_positive_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [5, 6.2, 7.002, 7.002, 8.02]
    constant = 2
    c1: EncryptedTensor = cs.encrypt(t1)

    c2 = c1 * constant

    t2 = cs.decrypt(c2)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info("✅ Homomorphic multiplication by a positive constant tests succeeded")


def test_homomorphic_multiply_by_a_negative_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [5, 6.2, 7.002, 7.002, 8.02]
    constant = -2
    c1: EncryptedTensor = cs.encrypt(t1)

    c2 = c1 * constant

    t2 = cs.decrypt(c2)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info("✅ Homomorphic multiplication by a negative constant tests succeeded")


def test_homomorphic_multiply_with_int_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [5, 6.2, 7.002, 7.002, 8.02]
    constant = 2
    c1: EncryptedTensor = cs.encrypt(t1)

    c2 = constant * c1

    t2 = cs.decrypt(c2)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with an integer constant tests succeeded"
    )


def test_homomorphic_multiply_with_positive_float_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [10000.0, 15000, 20000]
    constant = 1.05
    c1: EncryptedTensor = cs.encrypt(t1)

    c2 = constant * c1

    t2 = cs.decrypt(c2)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with a positive float constant tests succeeded"
    )


def test_homomorphic_multiply_with_negative_float_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [10000.0, 15000, 20000]
    constant = -1.05
    c1: EncryptedTensor = cs.encrypt(t1)

    c2 = constant * c1

    t2 = cs.decrypt(c2)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with a positive float constant tests succeeded"
    )


def test_homomorphic_addition():
    cs = LightPHE(algorithm_name="Paillier", key_size=30)

    t1 = [1.005, 2.05, 3.6, -4, 4.02, -3.5]
    t2 = [5, 6.2, -7.5, 8.02, -8.02, -4.5]

    c1: EncryptedTensor = cs.encrypt(t1)
    c2: EncryptedTensor = cs.encrypt(t2)

    c3 = c1 + c2

    restored_tensors = cs.decrypt(c3)

    for i, restored_tensor in enumerate(restored_tensors):
        if (
            (t1[i] >= 0 and t2[i] >= 0)
            or (t1[i] < 0 and t2[i] < 0)
            or (t1[i] + t2[i] >= 0)
        ):
            assert abs((t1[i] + t2[i]) - restored_tensor) < THRESHOLD
        elif t1[i] + t2[i] < 0:
            expected = convert_negative_float_to_int(
                t1[i] + t2[i], cs.cs.plaintext_modulo
            )
            assert abs(expected - restored_tensor) < THRESHOLD
        else:
            raise ValueError("else must not be called at all")

    with pytest.raises(ValueError):
        _ = c1 * c2

    logger.info("✅ Homomorphic addition tests succeeded")


def test_for_integer_tensor():
    cs = LightPHE(algorithm_name="Paillier")

    # suppose that these are normalized vectors
    a = [7.1, 5.2, 5.3, 2.4, 3.5, 4.6]
    b = [5.6, 3.7, 2.8, 4, 0, 5.9]

    expected_similarity = sum(x * y for x, y in zip(a, b))

    enc_a = cs.encrypt(a)

    fractions = enc_a.fractions

    # we expect to have same divisor for all items
    for fraction in fractions[1:]:
        assert fractions[0].divisor == fraction.divisor

    enc_a_times_b = enc_a * b

    a_times_b = cs.decrypt(enc_a_times_b)

    for i in range(0, len(a)):
        assert (
            abs(a[i] * b[i] - a_times_b[i]) < 0.1
        ), f"Expected {a[i] * b[i]}, got {a_times_b[i]}"

    # dot product
    encrypted_similarity = enc_a @ b
    decrypted_similarity = cs.decrypt(encrypted_similarity)[0]

    assert (
        abs(decrypted_similarity - expected_similarity) < 0.1
    ), f"expected {expected_similarity} but got {decrypted_similarity}"

    logger.info("✅ Integer tensor tests succeeded")


def test_real_world_embedding():
    cs = LightPHE(algorithm_name="Paillier")

    source_embedding = [float(format(random.uniform(1, 2), ".17f")) for _ in range(128)]
    logger.info(f"source image's embedding found - {len(source_embedding)}D")

    source_embedding_encrypted = cs.encrypt(source_embedding)
    logger.info("source embedding encrypted")

    target_embedding = [float(format(random.uniform(1, 2), ".17f")) for _ in range(128)]
    logger.info(f"target image's embedding found - {len(target_embedding)}D")

    # dot product to calculate encrypted similarity
    encrypted_similarity = source_embedding_encrypted @ target_embedding

    decrypted_similarity = cs.decrypt(encrypted_similarity)[0]

    expected_similarity = sum(x * y for x, y in zip(source_embedding, target_embedding))

    logger.info(
        f"ℹ️ expected similarity: {expected_similarity}, got {decrypted_similarity}"
    )

    assert (
        abs(expected_similarity - decrypted_similarity) < 0.1
    ), f"expected {expected_similarity} but got {decrypted_similarity}"

    logger.info("✅ Real world embedding test succeeded")
