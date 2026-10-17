import random
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_damgardgeislerkroigaard.py")

cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=50)


def test_api():
    tic = time.time()
    modulo = cs.cs.plaintext_modulo

    m1 = 3
    m2 = 4

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == (m1 + m2) % modulo

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == (m1 * m2) % modulo
    assert cs.decrypt(m2 * c1) == (m1 * m2) % modulo

    # negative plaintexts and addition wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-2)
    assert cs.decrypt(c3) == modulo - 2
    assert cs.decrypt(c1 + c3) == m1 - 2
    assert cs.decrypt(cs.encrypt(plaintext=modulo - 1) + c1) == m1 - 1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    logger.info(
        f"✅ Damgard-Geisler-Kroigaard api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_all_plaintexts_in_small_space():
    small_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=32)
    modulo = small_cs.cs.plaintext_modulo
    for m in range(modulo):
        assert small_cs.decrypt(small_cs.encrypt(plaintext=m)) == m
    logger.info(f"✅ Damgard-Geisler-Kroigaard restored all {modulo} plaintexts")


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", keys=cs.cs.keys)
    m1 = 2
    m2 = 5
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Damgard-Geisler-Kroigaard predefined keys test succeeded")


def test_encryption_with_public_key_only():
    public_cs = LightPHE(
        algorithm_name="Damgard-Geisler-Kroigaard",
        keys={"public_key": cs.cs.keys["public_key"]},
    )
    m1 = 6
    c1 = public_cs.encrypt(plaintext=m1)
    assert cs.decrypt(c1) == m1

    with pytest.raises(ValueError):
        public_cs.decrypt(c1)
    logger.info("✅ Damgard-Geisler-Kroigaard public key only test succeeded")


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=1024)
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 10) == m1 * 10

    # floats and tensors
    c3 = large_cs.encrypt(plaintext=1.5)
    assert large_cs.decrypt(c3 * 4) == 6
    enc_tensor = large_cs.encrypt([1.5, 2.25, 3.5], silent=True)
    assert large_cs.decrypt(enc_tensor) == [1.5, 2.25, 3.5]
    assert large_cs.decrypt(enc_tensor + enc_tensor) == [3.0, 4.5, 7.0]
    assert large_cs.decrypt(enc_tensor * 2) == [3.0, 4.5, 7.0]

    logger.info(
        f"✅ Damgard-Geisler-Kroigaard 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )


# secure comparison and private decision trees

protocol_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=256)
server_cs = LightPHE(
    algorithm_name="Damgard-Geisler-Kroigaard",
    keys={"public_key": protocol_cs.cs.keys["public_key"]},
)


def evaluate_plain_tree(tree, features):
    while not isinstance(tree, int):
        feature_index, threshold, left, right = tree
        tree = left if features[feature_index] <= threshold else right
    return tree


def run_private_decision_tree(tree, features, bit_length):
    # client
    encrypted_features = protocol_cs.encrypt_decision_tree_input(
        features=features, bit_length=bit_length
    )
    # server
    encrypted_comparisons, server_state = server_cs.evaluate_decision_tree_comparisons(
        tree=tree, encrypted_features=encrypted_features
    )
    # client
    encrypted_answers = protocol_cs.answer_decision_tree_comparisons(
        encrypted_comparisons=encrypted_comparisons
    )
    # server
    encrypted_leaves = server_cs.evaluate_decision_tree_leaves(
        server_state=server_state, encrypted_answers=encrypted_answers
    )
    # client
    return protocol_cs.decrypt_decision_tree_output(encrypted_leaves=encrypted_leaves)


def test_secure_comparison_all_pairs():
    tic = time.time()
    bit_length = 4
    for x in range(2**bit_length):
        encrypted_x = protocol_cs.encrypt_comparison_input(value=x, bit_length=bit_length)
        assert len(encrypted_x) == bit_length
        for y in range(2**bit_length):
            encrypted_result = server_cs.evaluate_comparison(
                encrypted_input=encrypted_x, value=y
            )
            assert len(encrypted_result) == bit_length + 1
            assert protocol_cs.decrypt_comparison(encrypted_result) == (x <= y)
    logger.info(
        f"✅ Damgard-Geisler-Kroigaard secure comparison test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_secure_comparison_edge_values():
    bit_length = 16
    max_value = 2**bit_length - 1
    for x, y in [(0, 0), (0, max_value), (max_value, 0), (max_value, max_value),
                 (12345, 12345), (12345, 12346), (12346, 12345)]:
        encrypted_x = protocol_cs.encrypt_comparison_input(value=x, bit_length=bit_length)
        encrypted_result = server_cs.evaluate_comparison(encrypted_input=encrypted_x, value=y)
        assert protocol_cs.decrypt_comparison(encrypted_result) == (x <= y)


def test_secure_comparison_invalid_inputs():
    with pytest.raises(ValueError, match="must be integers"):
        protocol_cs.encrypt_comparison_input(value=16, bit_length=4)

    with pytest.raises(ValueError, match="must be integers"):
        protocol_cs.encrypt_comparison_input(value=-1, bit_length=4)

    encrypted_x = protocol_cs.encrypt_comparison_input(value=3, bit_length=4)
    with pytest.raises(ValueError, match="must be integers"):
        server_cs.evaluate_comparison(encrypted_input=encrypted_x, value=16)

    # 4-bit plaintext space cannot hold the comparison of 8-bit values
    with pytest.raises(ValueError, match="too small to compare"):
        cs.encrypt_comparison_input(value=3, bit_length=8)

    # client side requires private key
    with pytest.raises(ValueError, match="You must have private key"):
        server_cs.decrypt_comparison(
            server_cs.evaluate_comparison(encrypted_input=encrypted_x, value=5)
        )


def test_private_decision_tree():
    tic = time.time()
    # loan approval: features are 0 (age), 1 (income in thousand dollars) and
    # 2 (number of open loans), and leaves are credit limits in thousand dollars.
    #
    #                         F1: income <= 40?
    #                       /yes                 \no
    #           F0: age <= 25?               F2: open loans <= 2?
    #            /yes      \no                 /yes             \no
    #           0    F2: open loans <= 1?   F1: income <= 100?   10
    #                  /yes       \no         /yes       \no
    #                 5            0         20           50
    tree = (1, 40, (0, 25, 0, (2, 1, 5, 0)), (2, 2, (1, 100, 20, 50), 10))
    bit_length = 8

    samples = [
        [22, 30, 0],
        [30, 30, 1],
        [30, 30, 3],
        [40, 41, 0],
        [40, 100, 2],
        [40, 101, 2],
        [50, 200, 3],
        [25, 40, 1],
    ]
    for features in samples:
        expected = evaluate_plain_tree(tree, features)
        # comparisons are flipped randomly, so run each sample several times
        for _ in range(3):
            assert run_private_decision_tree(tree, features, bit_length) == expected

    logger.info(
        f"✅ Damgard-Geisler-Kroigaard private decision tree test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_private_decision_tree_all_inputs():
    tree = (0, 1, (1, 2, 1, 2), (1, 0, 3, (0, 2, 4, 5)))
    bit_length = 2
    for a in range(4):
        for b in range(4):
            assert run_private_decision_tree(tree, [a, b], bit_length) == (
                evaluate_plain_tree(tree, [a, b])
            )


def test_private_decision_tree_single_leaf():
    assert run_private_decision_tree(7, [1, 2], 4) == 7


def test_private_decision_tree_invalid_inputs():
    encrypted_features = protocol_cs.encrypt_decision_tree_input(
        features=[1, 2], bit_length=4
    )

    with pytest.raises(ValueError, match="Feature index 2 does not exist"):
        server_cs.evaluate_decision_tree_comparisons(
            tree=(2, 1, 0, 1), encrypted_features=encrypted_features
        )

    with pytest.raises(ValueError, match="Decision node must be"):
        server_cs.evaluate_decision_tree_comparisons(
            tree=(0, 0, 1), encrypted_features=encrypted_features
        )

    with pytest.raises(ValueError, match="Leaf labels must be"):
        _, server_state = server_cs.evaluate_decision_tree_comparisons(
            tree=(0, 1, 0, -1), encrypted_features=encrypted_features
        )
        server_cs.evaluate_decision_tree_leaves(
            server_state=server_state,
            encrypted_answers=[protocol_cs.cs.encrypt(plaintext=0)],
        )

    _, server_state = server_cs.evaluate_decision_tree_comparisons(
        tree=(0, 1, 0, 1), encrypted_features=encrypted_features
    )
    with pytest.raises(ValueError, match="Expected 1 answers but got 0"):
        server_cs.evaluate_decision_tree_leaves(
            server_state=server_state, encrypted_answers=[]
        )


def test_unsupported_algorithms():
    paillier_cs = LightPHE(algorithm_name="Paillier", key_size=50)
    with pytest.raises(ValueError, match="does not support secure comparison"):
        paillier_cs.encrypt_comparison_input(value=1, bit_length=4)

    with pytest.raises(ValueError, match="does not support secure comparison"):
        paillier_cs.evaluate_comparison(encrypted_input=[1], value=1)

    with pytest.raises(ValueError, match="does not support private decision tree"):
        paillier_cs.encrypt_decision_tree_input(features=[1], bit_length=4)

    with pytest.raises(ValueError, match="does not support private decision tree"):
        paillier_cs.evaluate_decision_tree_comparisons(
            tree=(0, 1, 0, 1), encrypted_features=[[1]]
        )


def run_argmax(values, bit_length):
    encrypted_values = [protocol_cs.encrypt(plaintext=value) for value in values]
    encrypted_index = server_cs.evaluate_argmax(
        encrypted_values=encrypted_values,
        bit_length=bit_length,
        client=protocol_cs.answer_argmax,
    )
    return protocol_cs.decrypt(encrypted_index)


def test_argmax():
    tic = time.time()
    cases = [
        [5],
        [3, 9],
        [9, 3],
        [7, 7],
        [1, 7, 3, 7],
        [0, 0, 0, 0],
        [255, 0, 254],
        [10, 20, 30, 40, 50],
        [50, 40, 30, 20, 10],
        [12, 200, 3, 199, 255, 17],
    ]
    for values in cases:
        # index of the first maximum on ties, like list.index(max(...))
        assert run_argmax(values, bit_length=8) == values.index(max(values))
    logger.info(
        f"✅ Damgard-Geisler-Kroigaard argmax test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_argmax_random_values():
    rng = random.Random(42)
    # masks are random, so the comparison arc wraps around u in some rounds
    for _ in range(30):
        bit_length = rng.choice([1, 4, 8, 12])
        values = [rng.randint(0, 2**bit_length - 1) for _ in range(rng.randint(1, 6))]
        assert run_argmax(values, bit_length) == values.index(max(values))


def test_argmax_of_linear_classifier():
    # client's encrypted features, server's private linear model with 3 classes
    features = [3, 1, 4]
    weights = [[1, 2, 0], [0, 1, 3], [2, 0, 1]]

    encrypted_features = [protocol_cs.encrypt(plaintext=feature) for feature in features]

    # server computes encrypted class scores homomorphically
    encrypted_scores = []
    for class_weights in weights:
        score = encrypted_features[0] * class_weights[0]
        for encrypted_feature, weight in zip(encrypted_features[1:], class_weights[1:]):
            score = score + encrypted_feature * weight
        encrypted_scores.append(score)

    encrypted_class = server_cs.evaluate_argmax(
        encrypted_values=encrypted_scores, bit_length=8, client=protocol_cs.answer_argmax
    )

    scores = [sum(w * f for w, f in zip(class_weights, features)) for class_weights in weights]
    assert protocol_cs.decrypt(encrypted_class) == scores.index(max(scores)) == 1


def test_argmax_client_sees_only_masked_values():
    values = [10, 200, 30]
    seen = []

    def client(message):
        seen.append(message["type"])
        return protocol_cs.answer_argmax(message)

    encrypted_values = [protocol_cs.encrypt(plaintext=value) for value in values]
    encrypted_index = server_cs.evaluate_argmax(
        encrypted_values=encrypted_values, bit_length=8, client=client
    )
    assert protocol_cs.decrypt(encrypted_index) == 1

    # 3 round trips for each of the remaining 2 values
    assert seen == ["masked_difference", "comparisons", "products"] * 2


def test_argmax_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=1024)
    values = [40000, 65535, 3, 65534]
    encrypted_values = [large_cs.encrypt(plaintext=value) for value in values]
    encrypted_index = large_cs.evaluate_argmax(
        encrypted_values=encrypted_values, bit_length=16, client=large_cs.answer_argmax
    )
    assert large_cs.decrypt(encrypted_index) == 1
    logger.info(
        f"✅ Damgard-Geisler-Kroigaard 1024-bit argmax test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_argmax_invalid_inputs():
    with pytest.raises(ValueError, match="at least one value"):
        server_cs.evaluate_argmax(
            encrypted_values=[], bit_length=8, client=protocol_cs.answer_argmax
        )

    with pytest.raises(ValueError, match="too small for argmax"):
        server_cs.evaluate_argmax(
            encrypted_values=[protocol_cs.encrypt(plaintext=1)] * 2,
            bit_length=protocol_cs.cs.plaintext_modulo.bit_length(),
            client=protocol_cs.answer_argmax,
        )

    with pytest.raises(ValueError, match="Unknown argmax message type"):
        protocol_cs.answer_argmax({"type": "unknown", "payload": []})

    # client side requires private key
    with pytest.raises(ValueError, match="You must have private key"):
        server_cs.answer_argmax({"type": "products", "payload": []})

    paillier_cs = LightPHE(algorithm_name="Paillier", key_size=50)
    with pytest.raises(ValueError, match="does not support encrypted argmax"):
        paillier_cs.evaluate_argmax(
            encrypted_values=[paillier_cs.encrypt(plaintext=1)],
            bit_length=4,
            client=paillier_cs.answer_argmax,
        )


def test_decision_tree_input_arguments():
    # Damgard-Geisler-Kroigaard expects features and bit_length, not bits and depth
    with pytest.raises(ValueError, match="with bits and depth"):
        protocol_cs.encrypt_decision_tree_input(bits=[1, 0], depth=2)

    with pytest.raises(ValueError, match="not both"):
        protocol_cs.encrypt_decision_tree_input(features=[1], bit_length=4, depth=2)

    with pytest.raises(ValueError, match="must be passed together"):
        protocol_cs.encrypt_decision_tree_input(features=[1])

    with pytest.raises(ValueError, match="must be passed together"):
        protocol_cs.encrypt_decision_tree_input(bit_length=4)

    # Ishai-Paskin expects bits and depth, not features and bit_length
    ishai_paskin_cs = LightPHE(algorithm_name="Ishai-Paskin", key_size=50)
    with pytest.raises(ValueError, match="with features and bit_length"):
        ishai_paskin_cs.encrypt_decision_tree_input(features=[1], bit_length=4)

    with pytest.raises(ValueError, match="must be passed together"):
        ishai_paskin_cs.encrypt_decision_tree_input(bits=[1])


# examples in the readme

readme_customer_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard")


def build_readme_server_cs(tmp_path):
    # customer shares only the public key with the server
    public_key_file = str(tmp_path / "public.txt")
    readme_customer_cs.export_keys(target_file=public_key_file, public=True)
    server = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_file=public_key_file)
    assert server.cs.keys.get("private_key") is None
    return server


def test_readme_decision_tree(tmp_path):
    tic = time.time()
    customer_cs = readme_customer_cs
    bank_cs = build_readme_server_cs(tmp_path)

    # features are 0 (age), 1 (income in thousand dollars) and 2 (number of open loans),
    # and leaves are credit limits in thousand dollars.
    #
    #                   F1: income <= 40?
    #                  /yes                \no
    #        F0: age <= 25?          F2: open loans <= 2?
    #         /yes      \no            /yes           \no
    #        0           5            20              10
    credit_limit_tree = (1, 40, (0, 25, 0, 5), (2, 2, 20, 10))

    # the customer in the readme first, then every path of the tree drawn in the readme
    expected_limits = {
        (30, 75, 1): 20,
        (25, 40, 0): 0,
        (26, 40, 0): 5,
        (30, 41, 2): 20,
        (30, 41, 3): 10,
    }

    for features, expected_limit in expected_limits.items():
        encrypted_features = customer_cs.encrypt_decision_tree_input(
            features=list(features), bit_length=8
        )
        encrypted_comparisons, bank_state = bank_cs.evaluate_decision_tree_comparisons(
            tree=credit_limit_tree, encrypted_features=encrypted_features
        )
        encrypted_answers = customer_cs.answer_decision_tree_comparisons(
            encrypted_comparisons
        )
        encrypted_leaves = bank_cs.evaluate_decision_tree_leaves(
            server_state=bank_state, encrypted_answers=encrypted_answers
        )
        assert (
            customer_cs.decrypt_decision_tree_output(encrypted_leaves) == expected_limit
        ), features

    # bank cannot run the customer's steps
    with pytest.raises(ValueError, match="private key"):
        bank_cs.answer_decision_tree_comparisons(encrypted_comparisons)

    with pytest.raises(ValueError, match="private key"):
        bank_cs.decrypt_decision_tree_output(encrypted_leaves)

    logger.info(
        f"✅ Damgard-Geisler-Kroigaard decision tree example in readme succeeded in {time.time() - tic:.2f} seconds"
    )


def test_readme_secure_comparison(tmp_path):
    client_cs = readme_customer_cs
    auction_cs = build_readme_server_cs(tmp_path)

    encrypted_bid = client_cs.encrypt_comparison_input(value=120, bit_length=16)
    encrypted_result = auction_cs.evaluate_comparison(
        encrypted_input=encrypted_bid, value=150
    )
    assert client_cs.decrypt_comparison(encrypted_result) is True

    # bid above the reserve price
    encrypted_result = auction_cs.evaluate_comparison(
        encrypted_input=encrypted_bid, value=100
    )
    assert client_cs.decrypt_comparison(encrypted_result) is False

    # server cannot learn the result
    with pytest.raises(ValueError, match="private key"):
        auction_cs.decrypt_comparison(encrypted_result)

    logger.info("✅ Damgard-Geisler-Kroigaard secure comparison example in readme succeeded")


def test_readme_argmax(tmp_path):
    tic = time.time()
    client_cs = readme_customer_cs
    model_cs = build_readme_server_cs(tmp_path)

    encrypted_features = [client_cs.encrypt(feature) for feature in [3, 1, 4]]

    weights = [[1, 2, 0], [0, 1, 3], [2, 0, 1]]
    encrypted_scores = []
    for class_weights in weights:
        score = encrypted_features[0] * class_weights[0]
        for encrypted_feature, weight in zip(encrypted_features[1:], class_weights[1:]):
            score = score + encrypted_feature * weight
        encrypted_scores.append(score)

    encrypted_class = model_cs.evaluate_argmax(
        encrypted_values=encrypted_scores, bit_length=8, client=client_cs.answer_argmax
    )
    assert "private_key" not in encrypted_class.keys
    assert client_cs.decrypt(encrypted_class) == 1

    # server cannot decrypt the predicted class
    with pytest.raises(ValueError, match="private key"):
        model_cs.decrypt(encrypted_class)

    logger.info(
        f"✅ Damgard-Geisler-Kroigaard argmax example in readme succeeded in {time.time() - tic:.2f} seconds"
    )
