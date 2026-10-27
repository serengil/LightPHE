import itertools
import math
import random

import pytest

from lightphe import LightPHE
from lightphe.commons import classifiers
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_classifiers.py")

# 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
# they are not secure, and are for testing only.
client_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=512)
server_cs = LightPHE(
    algorithm_name="Damgard-Geisler-Kroigaard",
    keys={"public_key": client_cs.cs.keys["public_key"]},
)


def classify_hyperplane(features, weights, bit_length, biases=None):
    encrypted_features = [client_cs.encrypt(x) for x in features]
    encrypted_class = server_cs.evaluate_hyperplane(
        encrypted_features, weights, bit_length, client=client_cs.answer_argmax, biases=biases
    )
    return client_cs.decrypt(encrypted_class)


def classify_naive_bayes(features, priors, likelihoods):
    domain_sizes = [len(values) for values in likelihoods[0]]
    encrypted_input = client_cs.encrypt_naive_bayes_input(features, domain_sizes)
    encrypted_class = server_cs.evaluate_naive_bayes(
        encrypted_input, priors, likelihoods, client=client_cs.answer_argmax
    )
    return client_cs.decrypt(encrypted_class)


def test_hyperplane_matches_plain_argmax():
    random.seed(1)
    for _ in range(8):
        weights = [[random.randint(-20, 20) for _ in range(6)] for _ in range(4)]
        biases = [random.randint(-100, 100) for _ in range(4)]
        features = [random.randint(-30, 30) for _ in range(6)]
        scores = [sum(w * x for w, x in zip(ws, features)) + b for ws, b in zip(weights, biases)]
        # scores are in (-2^13, 2^13)
        assert classify_hyperplane(features, weights, 13, biases) == scores.index(max(scores))

    logger.info("✅ Encrypted hyperplane classification matches plain argmax")


def test_hyperplane_ties_and_binary_classification():
    # earlier class on ties
    assert classify_hyperplane([1, 1], [[2, 0], [0, 2], [1, 1]], 4) == 0

    # a binary linear classifier is a hyperplane of two classes: 0 and w
    weights = [3, -2, 5]
    for features in [[1, 4, 0], [2, 1, 1]]:
        positive = sum(w * x for w, x in zip(weights, features)) - 4 > 0
        assert classify_hyperplane(features, [[0, 0, 0], weights], 8, biases=[0, -4]) == int(positive)


def test_credit_approval_with_logistic_regression():
    """
    Bank owns a logistic regression model, and a customer applies with encrypted features.
    Customer learns only whether the loan is approved, and bank learns nothing.
    """
    # features: income in thousands, debt in thousands, years of employment, late payments
    float_weights = [0.042, -0.065, 0.31, -0.9]
    float_bias = -1.2
    weights = [[0, 0, 0, 0], [round(w * 1000) for w in float_weights]]
    biases = [0, round(float_bias * 1000)]

    for features in [[85, 20, 6, 0], [30, 45, 1, 3], [55, 10, 3, 1]]:
        logit = sum(w * x for w, x in zip(float_weights, features)) + float_bias
        approved = classify_hyperplane(features, weights, bit_length=16, biases=biases)
        assert approved == int(logit > 0)


def test_naive_bayes_matches_plain_prediction():
    random.seed(2)
    domain_sizes = [2, 3, 2]
    priors = [0.5, 0.3, 0.2]
    likelihoods = []
    for _ in priors:
        class_likelihoods = []
        for size in domain_sizes:
            values = [random.uniform(0.05, 1) for _ in range(size)]
            class_likelihoods.append([v / sum(values) for v in values])
        likelihoods.append(class_likelihoods)

    for features in itertools.product(*[range(size) for size in domain_sizes]):
        scores = [
            math.log(priors[c]) + sum(math.log(likelihoods[c][j][v]) for j, v in enumerate(features))
            for c in range(len(priors))
        ]
        ranked = sorted(scores, reverse=True)
        # quantization with precision 3 cannot separate scores closer than about 10^-2
        if ranked[0] - ranked[1] < 1e-2:
            continue
        assert classify_naive_bayes(list(features), priors, likelihoods) == scores.index(max(scores))

    logger.info("✅ Encrypted naive bayes matches plain prediction")


def test_medical_diagnosis_with_naive_bayes():
    """
    Clinic owns a naive bayes model trained on patient records, and a patient sends encrypted
    symptoms. Patient learns only the most likely diagnosis, and clinic learns nothing.
    """
    # symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
    # diagnoses: cold, flu, allergy
    records = {
        0: [(0, 2, 0), (0, 2, 1), (1, 2, 0), (0, 1, 0), (0, 2, 0)],
        1: [(1, 1, 1), (1, 2, 1), (1, 1, 1), (1, 1, 0), (0, 1, 1)],
        2: [(0, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0, 0)],
    }
    domain_sizes = [2, 3, 2]
    total = sum(len(rows) for rows in records.values())
    priors = [len(records[c]) / total for c in range(3)]

    # laplace smoothing keeps probabilities positive
    likelihoods = [
        [
            [
                (sum(row[j] == v for row in records[c]) + 1) / (len(records[c]) + size)
                for v in range(size)
            ]
            for j, size in enumerate(domain_sizes)
        ]
        for c in range(3)
    ]

    assert classify_naive_bayes([1, 1, 1], priors, likelihoods) == 1  # flu
    assert classify_naive_bayes([0, 2, 0], priors, likelihoods) == 0  # cold
    assert classify_naive_bayes([0, 0, 0], priors, likelihoods) == 2  # allergy


def test_quantization_of_naive_bayes():
    priors, likelihoods, bit_length = classifiers.quantize_naive_bayes(
        priors=[0.25, 0.75], likelihoods=[[[0.5, 0.5]], [[0.1, 0.9]]], precision=3
    )
    # log probabilities are shifted by their minimum, so the smallest one is 0
    assert min(priors) == 0 and min(min(values) for c in likelihoods for values in c) == 0
    assert all(x >= 0 for c in likelihoods for values in c for x in values)
    largest = max(p + sum(max(v) for v in c) for p, c in zip(priors, likelihoods))
    assert largest < 2**bit_length


def test_invalid_inputs():
    encrypted_features = [client_cs.encrypt(x) for x in [1, 2]]

    with pytest.raises(ValueError, match="same number of weights"):
        server_cs.evaluate_hyperplane(encrypted_features, [[1, 2], [3]], 8, client_cs.answer_argmax)
    with pytest.raises(ValueError, match="must be integers"):
        server_cs.evaluate_hyperplane(encrypted_features, [[1, 0.5]], 8, client_cs.answer_argmax)
    with pytest.raises(ValueError, match="list of 3 ciphertexts"):
        server_cs.evaluate_hyperplane(encrypted_features, [[1, 2, 3]], 8, client_cs.answer_argmax)
    with pytest.raises(ValueError, match="bias for each class"):
        server_cs.evaluate_hyperplane(
            encrypted_features, [[1, 2]], 8, client_cs.answer_argmax, biases=[1, 2]
        )
    with pytest.raises(ValueError, match="too small for argmax"):
        server_cs.evaluate_hyperplane(encrypted_features, [[1, 2]], 40, client_cs.answer_argmax)

    likelihoods = [[[0.5, 0.5]], [[0.2, 0.8]]]
    encrypted_input = client_cs.encrypt_naive_bayes_input([1], [2])
    with pytest.raises(ValueError, match="Smooth zero probabilities"):
        server_cs.evaluate_naive_bayes(
            encrypted_input, [0.5, 0.5], [[[1.0, 0.0]], [[0.2, 0.8]]], client_cs.answer_argmax
        )
    with pytest.raises(ValueError, match="prior for each class"):
        server_cs.evaluate_naive_bayes(encrypted_input, [1.0], likelihoods, client_cs.answer_argmax)
    with pytest.raises(ValueError, match="domain sizes"):
        server_cs.evaluate_naive_bayes(
            client_cs.encrypt_naive_bayes_input([1], [3]), [0.5, 0.5], likelihoods,
            client_cs.answer_argmax,
        )
    with pytest.raises(ValueError, match="must be an integer in"):
        client_cs.encrypt_naive_bayes_input([2], [2])

    paillier = LightPHE(algorithm_name="Paillier", key_size=64)
    with pytest.raises(ValueError, match="does not support encrypted classification"):
        paillier.encrypt_naive_bayes_input([0], [2])
