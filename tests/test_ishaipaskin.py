import itertools
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ishaipaskin.py")

cs = LightPHE(algorithm_name="Ishai-Paskin", key_size=50)


def evaluate_in_plain(tree, bits):
    while not isinstance(tree, int):
        variable_index, tree_if_0, tree_if_1 = tree
        tree = tree_if_1 if bits[variable_index] == 1 else tree_if_0
    return tree


def find_depth(tree):
    if isinstance(tree, int):
        return 0
    return 1 + max(find_depth(tree[1]), find_depth(tree[2]))


def assert_tree(tree, num_inputs, depth=None):
    depth = depth or max(1, find_depth(tree))
    for bits in itertools.product([0, 1], repeat=num_inputs):
        encrypted_input = cs.encrypt_decision_tree_input(bits=list(bits), depth=depth)
        output = cs.evaluate_decision_tree(tree=tree, encrypted_input=encrypted_input)
        assert cs.decrypt(output) == evaluate_in_plain(tree, bits), bits


def test_api():
    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition and scalar multiplication inherited from Damgard-Jurik
    assert cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Ishai-Paskin api test succeeded")


def test_encryption_levels():
    n = cs.cs.keys["public_key"]["n"]
    for level in range(1, 5):
        # plaintext space of level s is Z_{n^s}
        for m in [0, 1, 12345, n + 7, pow(n, level) - 1]:
            m = m % pow(n, level)
            c = cs.cs.encrypt_at_level(plaintext=m, level=level)
            assert c < pow(n, level + 1)
            assert cs.cs.decrypt_at_level(ciphertext=c, level=level) == m

        # level s is additively homomorphic in Z_{n^s}
        m1, m2 = pow(n, level) - 3, 10
        c1 = cs.cs.encrypt_at_level(plaintext=m1, level=level)
        c2 = cs.cs.encrypt_at_level(plaintext=m2, level=level)
        product = (c1 * c2) % pow(n, level + 1)
        assert cs.cs.decrypt_at_level(ciphertext=product, level=level) == 7
    logger.info("✅ Ishai-Paskin encryption levels test succeeded")


def test_boolean_trees():
    x0_or_x1 = (0, (1, 0, 1), 1)
    x0_and_x1 = (0, 0, (1, 0, 1))
    not_x1 = (1, 1, 0)
    assert_tree(x0_or_x1, num_inputs=2)
    assert_tree(x0_and_x1, num_inputs=2)
    assert_tree(not_x1, num_inputs=2)

    # shared sub trees (DAG) are evaluated once
    x2_is_0 = (2, 1, 0)
    x2_is_1 = (2, 0, 1)
    x1_xor_x2 = (1, x2_is_1, x2_is_0)
    x1_xnor_x2 = (1, x2_is_0, x2_is_1)
    x0_xor_x1_xor_x2 = (0, x1_xor_x2, x1_xnor_x2)
    assert_tree(x0_xor_x1_xor_x2, num_inputs=3)

    majority = (0, (1, 0, (2, 0, 1)), (1, (2, 0, 1), 1))
    assert_tree(majority, num_inputs=3)
    logger.info("✅ Ishai-Paskin boolean trees test succeeded")


def test_decision_tree_with_non_binary_leaves():
    # leaves at different depths returning class labels
    decision_tree = (0, (1, 10, (2, 20, 30)), 40)
    assert_tree(decision_tree, num_inputs=3)

    # encrypted input can be prepared for deeper trees than evaluated one
    assert_tree(decision_tree, num_inputs=3, depth=5)

    # constant tree
    assert_tree(99, num_inputs=1)
    logger.info("✅ Ishai-Paskin decision tree test succeeded")


def test_output_is_rerandomized():
    tree = (0, (1, 0, 1), 1)
    encrypted_input = cs.encrypt_decision_tree_input(bits=[1, 0], depth=2)
    output1 = cs.evaluate_decision_tree(tree=tree, encrypted_input=encrypted_input)
    output2 = cs.evaluate_decision_tree(tree=tree, encrypted_input=encrypted_input)

    # output always wraps as many layers as the tree depth
    assert output1.value[0] == output2.value[0] == 2
    assert output1.value[1] != output2.value[1]
    assert cs.decrypt(output1) == cs.decrypt(output2) == 1
    logger.info("✅ Ishai-Paskin rerandomization test succeeded")


def test_credit_limit_example_in_readme(tmp_path):
    # bank's secret tree: Q0 = has stable income?, Q1 = has existing debt?,
    # Q2 = owns a house?, leaves are credit limits in thousand dollars
    credit_limit_tree = (0, (2, 0, 5), (1, 20, (2, 5, 10)))

    # customer builds the cryptosystem and keeps the private key
    customer_cs = LightPHE(algorithm_name="Ishai-Paskin", key_size=50)

    # customer shares only the public key with the bank
    public_key_file = str(tmp_path / "public.txt")
    customer_cs.export_keys(target_file=public_key_file, public=True)

    # bank builds its own cryptosystem with the customer's public key
    bank_cs = LightPHE(algorithm_name="Ishai-Paskin", key_file=public_key_file)
    assert bank_cs.cs.keys.get("private_key") is None

    # every path of the tree drawn in the readme
    expected_limits = {
        (0, 0, 0): 0,
        (0, 1, 0): 0,
        (0, 0, 1): 5,
        (0, 1, 1): 5,
        (1, 0, 0): 20,
        (1, 0, 1): 20,
        (1, 1, 0): 5,
        (1, 1, 1): 10,
    }

    for answers, expected_limit in expected_limits.items():
        # customer encrypts the answers and sends them to the bank
        encrypted_answers = customer_cs.encrypt_decision_tree_input(
            bits=list(answers), depth=3
        )

        # bank runs its tree on encrypted answers
        encrypted_limit = bank_cs.evaluate_decision_tree(
            tree=credit_limit_tree, encrypted_input=encrypted_answers
        )
        assert "private_key" not in encrypted_limit.keys

        # customer decrypts the result
        assert customer_cs.decrypt(encrypted_limit) == expected_limit, answers

    # bank cannot decrypt the result
    with pytest.raises(ValueError, match="private key"):
        bank_cs.decrypt(encrypted_limit)

    # output can only be decrypted, homomorphic operations are not supported
    with pytest.raises(ValueError, match="can only be decrypted"):
        _ = encrypted_limit + encrypted_limit

    with pytest.raises(ValueError, match="can only be decrypted"):
        _ = encrypted_limit * 2

    with pytest.raises(ValueError, match="can only be decrypted"):
        customer_cs.regenerate_ciphertext(encrypted_limit)
    logger.info("✅ Ishai-Paskin credit limit example in readme succeeded")


def test_invalid_inputs():
    encrypted_input = cs.encrypt_decision_tree_input(bits=[1, 0], depth=1)

    with pytest.raises(ValueError, match="deeper than"):
        cs.evaluate_decision_tree(tree=(0, (1, 0, 1), 1), encrypted_input=encrypted_input)

    with pytest.raises(ValueError, match="out of input range"):
        cs.evaluate_decision_tree(tree=(2, 0, 1), encrypted_input=encrypted_input)

    with pytest.raises(ValueError, match="int leaf or a tuple"):
        cs.evaluate_decision_tree(tree=(0, 1), encrypted_input=encrypted_input)

    with pytest.raises(ValueError, match="bits"):
        cs.encrypt_decision_tree_input(bits=[2], depth=1)

    with pytest.raises(ValueError, match="depth"):
        cs.encrypt_decision_tree_input(bits=[1], depth=0)
    logger.info("✅ Ishai-Paskin invalid inputs test succeeded")


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Ishai-Paskin", key_size=1024)
    majority = (0, (1, 0, (2, 0, 1)), (1, (2, 0, 1), 1))
    for bits in [(1, 0, 1), (0, 1, 0)]:
        encrypted_input = large_cs.encrypt_decision_tree_input(bits=list(bits), depth=3)
        output = large_cs.evaluate_decision_tree(tree=majority, encrypted_input=encrypted_input)
        assert large_cs.decrypt(output) == evaluate_in_plain(majority, bits)
    logger.info(
        f"✅ Ishai-Paskin 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )
