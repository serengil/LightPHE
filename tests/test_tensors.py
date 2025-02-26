# built-in dependencies
import time
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
    assert isinstance(decrypted_tensors, list)

    for i, decrypted_tensor in enumerate(decrypted_tensors):
        expected_tensor = tensor[i]
        assert abs(expected_tensor - decrypted_tensor) <= THRESHOLD

    logger.info("✅ Tensor tests succeeded")


def test_homomorphic_multiplication():
    cs = LightPHE(algorithm_name="RSA")

    t1 = [1.005, 2.05, -3.5, 3.1, -4]
    t2 = [5, 6.2, -7.002, -7.1, 8.02]

    c1 = cs.encrypt(t1)
    c2 = cs.encrypt(t2)

    assert isinstance(c1, EncryptedTensor)
    assert isinstance(c2, EncryptedTensor)

    c3 = c1 * c2

    restored_tensors = cs.decrypt(c3)
    assert isinstance(restored_tensors, list)

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
    c1 = cs.encrypt(t1)

    c2 = c1 * constant

    t2 = cs.decrypt(c2)
    assert isinstance(t2, list)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info("✅ Homomorphic multiplication by a positive constant tests succeeded")


def test_homomorphic_multiply_by_a_negative_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [5, 6.2, 7.002, 7.002, 8.02]
    constant = -2
    c1 = cs.encrypt(t1)
    assert isinstance(c1, EncryptedTensor)

    c2 = c1 * constant

    t2 = cs.decrypt(c2)
    assert isinstance(t2, list)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info("✅ Homomorphic multiplication by a negative constant tests succeeded")


def test_homomorphic_multiply_with_int_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [5, 6.2, 7.002, 7.002, 8.02]
    constant = 2
    c1 = cs.encrypt(t1)
    assert isinstance(c1, EncryptedTensor)

    c2 = constant * c1

    t2 = cs.decrypt(c2)
    assert isinstance(t2, list)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with an integer constant tests succeeded"
    )


def test_homomorphic_multiply_with_positive_float_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [10000.0, 15000, 20000]
    constant = 1.05
    c1 = cs.encrypt(t1)

    c2 = constant * c1

    t2 = cs.decrypt(c2)
    assert isinstance(t2, list)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with a positive float constant tests succeeded"
    )


def test_homomorphic_multiply_with_negative_float_constant():
    cs = LightPHE(algorithm_name="Paillier")

    t1 = [10000.0, 15000, 20000]
    constant = -1.05
    c1 = cs.encrypt(t1)

    c2 = constant * c1

    t2 = cs.decrypt(c2)
    assert isinstance(t2, list)

    for i, restored_tensor in enumerate(t2):
        assert abs((t1[i] * constant) - restored_tensor) < THRESHOLD

    logger.info(
        "✅ Homomorphic multiplication with a positive float constant tests succeeded"
    )


def test_homomorphic_addition():
    cs = LightPHE(algorithm_name="Paillier", key_size=30)

    t1 = [1.005, 2.05, 3.6, -4, 4.02, -3.5]
    t2 = [5, 6.2, -7.5, 8.02, -8.02, -4.5]

    c1 = cs.encrypt(t1)
    c2 = cs.encrypt(t2)
    assert isinstance(c1, EncryptedTensor)
    assert isinstance(c2, EncryptedTensor)

    c3 = c1 + c2

    restored_tensors = cs.decrypt(c3)
    assert isinstance(restored_tensors, list)

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


@pytest.mark.parametrize(
    "algorithm_name",
    [
        "Paillier",
        "Damgard-Jurik",
        "Okamoto-Uchiyama",
        # "Exponential-ElGamal",
        # "EllipticCurve-ElGamal",
    ],
)
def test_for_integer_tensor(algorithm_name):
    cs = LightPHE(algorithm_name=algorithm_name)

    # suppose that these are normalized vectors
    a = [7.11, 5.22, 5.33, 2.44, 3.55, 4.66]
    b = [5.66, 3.77, 2.88, 4, 0, 5.99]

    expected_similarity = sum(x * y for x, y in zip(a, b))

    enc_a = cs.encrypt(a, silent=True)
    assert isinstance(enc_a, EncryptedTensor)

    fractions = enc_a.fractions

    # we expect to have same divisor for all items
    for fraction in fractions[1:]:
        assert fractions[0].divisor == fraction.divisor

    enc_a_times_b = enc_a * b

    a_times_b = cs.decrypt(enc_a_times_b)
    assert isinstance(a_times_b, list)

    for i in range(0, len(a)):
        assert (
            abs(a[i] * b[i] - a_times_b[i]) < 0.1
        ), f"Expected {a[i] * b[i]}, got {a_times_b[i]}"

    # dot product
    encrypted_similarity = enc_a @ b
    decrypted_similarities = cs.decrypt(encrypted_similarity)
    assert isinstance(decrypted_similarities, list)
    assert len(decrypted_similarities) > 0
    decrypted_similarity = decrypted_similarities[0]

    assert abs(decrypted_similarity - expected_similarity) < 0.1, (
        f"expected {expected_similarity} but got {decrypted_similarity}."
        f"Diff = {abs(expected_similarity - decrypted_similarity)}"
    )

    logger.info(f"✅ Tensor tests succeeded for {algorithm_name}")


@pytest.mark.parametrize(
    "algorithm_name",
    [
        "Paillier",
        "Damgard-Jurik",
        "Okamoto-Uchiyama",
        # "Exponential-ElGamal",
        # "EllipticCurve-ElGamal",
    ],
)
def test_real_world_embedding(algorithm_name):
    logger.info("🧪 Real world embedding experiment is running")
    cs = LightPHE(algorithm_name=algorithm_name, precision=17)

    # suppose that source and target embeddings are normalized vectors

    global_tic = time.time()

    n_dims = 4096

    source_embedding = [
        float(format(random.uniform(1, 2), ".17f")) for _ in range(n_dims)
    ]

    # Randomly choose 3682 indices to set to zero - similar to VGG-Face
    zero_indices = random.sample(range(n_dims), int(n_dims * 0.9))
    for idx in zero_indices:
        source_embedding[idx] = 0.0

    logger.info(f"🤖 source image's embedding found - {len(source_embedding)}D")

    tic = time.time()
    source_embedding_encrypted = cs.encrypt(source_embedding)
    assert isinstance(source_embedding_encrypted, EncryptedTensor)
    toc = time.time()
    logger.info(f"👨‍🔬 source embedding encrypted in {toc-tic} seconds")

    target_embedding = [
        float(format(random.uniform(1, 2), ".17f")) for _ in range(4096)
    ]
    logger.info(f"🤖 target image's embedding found - {len(target_embedding)}D")

    # dot product to calculate encrypted similarity
    tic = time.time()
    encrypted_similarity = source_embedding_encrypted @ target_embedding
    toc = time.time()

    logger.info(f"🧮 encrypted similarity found in {toc - tic} seconds")

    tic = time.time()
    decrypted_similarities = cs.decrypt(encrypted_similarity)
    toc = time.time()
    assert isinstance(decrypted_similarities, list)
    assert len(decrypted_similarities) > 0
    decrypted_similarity = decrypted_similarities[0]

    logger.info(f"🔑 encrypted similarity decrypted in {toc - tic} seconds")

    expected_similarity = sum(x * y for x, y in zip(source_embedding, target_embedding))

    logger.info(
        f"ℹ️ expected similarity: {expected_similarity}, got {decrypted_similarity}."
        f"Difference: {abs(expected_similarity - decrypted_similarity)}."
    )

    assert (
        abs(expected_similarity - decrypted_similarity) < 0.1
    ), f"expected {expected_similarity} but got {decrypted_similarity}"

    global_toc = time.time()
    duration = global_toc - global_tic

    logger.info(
        f"✅ Real world embedding test succeeded with {algorithm_name} in {duration} seconds"
    )
