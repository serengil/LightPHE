# built-in dependencies
import math
from typing import Any, Callable, List, Optional, Tuple

# Classification over encrypted data. Client (private key owner) encrypts its features,
# and server evaluates its private model on them, so client learns only the predicted
# class, and server learns nothing about the features.
#   - hyperplane: class scores <w_i, x> + b_i are linear in the encrypted features.
#       They are shifted by 2^bit_length to be non-negative, which keeps the argmax.
#   - naive bayes: client encrypts each categorical feature as a one-hot vector, so the
#       score log P(c) + sum of log P(x_j | c) is linear in it. Log probabilities are
#       quantized, and the log probabilities of each feature are shifted by their minimum,
#       which adds the same constant to scores of all classes, so it keeps the argmax.
#   - argmax: interactive argmax of Damgard-Geisler-Kroigaard on encrypted scores.
# Ref: Bost, R., Popa, R. A., Tu, S., Goldwasser, S. (2015). Machine Learning
#   Classification over Encrypted Data. NDSS 2015.

# pylint: disable=too-many-arguments, too-many-locals


def evaluate_hyperplane(
    cs: Any,
    encrypted_features: List[Any],
    weights: List[List[int]],
    biases: List[int],
    bit_length: int,
    client: Callable[[dict], List[int]],
) -> Any:
    """
    Find the class of the greatest score <w_i, x> + b_i for encrypted features x
    Args:
        cs (Homomorphic): Damgard-Geisler-Kroigaard cryptosystem having the public key
        encrypted_features (list of ciphertexts): features encrypted by the client
        weights (list of list of int): weights of each class
        biases (list of int): bias of each class
        bit_length (int): absolute values of scores must be less than 2^bit_length
        client (callable): sends a message to the client and returns its response
    Returns:
        encrypted class (ciphertext): index of the predicted class
    """
    u = cs.plaintext_modulo
    offset = 1 << bit_length
    scores = []
    for class_weights, bias in zip(weights, biases):
        score = cs.encrypt(plaintext=(bias + offset) % u)
        for weight, feature in zip(class_weights, encrypted_features):
            if weight % u != 0:
                score = cs.add(score, cs.multiply_by_constant(feature, weight % u))
        scores.append(score)
    # scores are in [0, 2^(bit_length + 1)) after the shift
    return cs.evaluate_argmax(encrypted_values=scores, bit_length=bit_length + 1, client=client)


def quantize_naive_bayes(
    priors: List[float], likelihoods: List[List[List[float]]], precision: int
) -> Tuple[List[int], List[List[List[int]]], int]:
    """
    Quantize log probabilities of a naive bayes model to non-negative integers
    Args:
        priors (list of float): P(c) of each class
        likelihoods (list of list of list of float): P(x_j = v | c) for class c, feature j
            and value v, i.e. likelihoods[c][j][v]
        precision (int): number of decimal digits kept from log probabilities
    Returns:
        quantized priors (list of int)
        quantized likelihoods (list of list of list of int)
        bit length (int): scores are less than 2^bit_length
    """
    scale = 10**precision

    def log(probability: float) -> float:
        if not isinstance(probability, (int, float)) or not 0 < probability <= 1:
            raise ValueError(
                f"Probabilities must be in (0, 1], got {probability}. Smooth zero"
                " probabilities, e.g. with Laplace smoothing."
            )
        return math.log(probability)

    log_priors = [log(p) for p in priors]
    lowest_prior = min(log_priors)
    quantized_priors = [round((x - lowest_prior) * scale) for x in log_priors]

    features = len(likelihoods[0])
    quantized_likelihoods: List[List[List[int]]] = [[] for _ in likelihoods]
    for j in range(features):
        logs = [[log(p) for p in class_likelihoods[j]] for class_likelihoods in likelihoods]
        lowest = min(min(values) for values in logs)
        for c, values in enumerate(logs):
            quantized_likelihoods[c].append([round((x - lowest) * scale) for x in values])

    largest = max(
        prior + sum(max(values) for values in class_likelihoods)
        for prior, class_likelihoods in zip(quantized_priors, quantized_likelihoods)
    )
    return quantized_priors, quantized_likelihoods, max(1, largest.bit_length())


def encrypt_naive_bayes_input(
    cs: Any, features: List[int], domain_sizes: List[int]
) -> List[List[Any]]:
    """
    Encrypt categorical features as one-hot vectors. Runs on client side.
    Args:
        cs (Homomorphic): additively homomorphic cryptosystem
        features (list of int): value of each feature in [0, domain size)
        domain_sizes (list of int): number of values of each feature
    Returns:
        encrypted input (list of list of ciphertexts): E(1) at the value, E(0) elsewhere
    """
    return [
        [cs.encrypt(plaintext=int(value == feature)) for value in range(size)]
        for feature, size in zip(features, domain_sizes)
    ]


def evaluate_naive_bayes(
    cs: Any,
    encrypted_input: List[List[Any]],
    priors: List[int],
    likelihoods: List[List[List[int]]],
    bit_length: int,
    client: Callable[[dict], List[int]],
) -> Any:
    """
    Find the most probable class of a naive bayes model for encrypted one-hot features
    Args:
        cs (Homomorphic): Damgard-Geisler-Kroigaard cryptosystem having the public key
        encrypted_input (list of list of ciphertexts): output of encrypt_naive_bayes_input
        priors (list of int): quantized log priors
        likelihoods (list of list of list of int): quantized log likelihoods
        bit_length (int): scores are less than 2^bit_length
        client (callable): sends a message to the client and returns its response
    Returns:
        encrypted class (ciphertext): index of the predicted class
    """
    u = cs.plaintext_modulo
    scores = []
    for prior, class_likelihoods in zip(priors, likelihoods):
        score = cs.encrypt(plaintext=prior % u)
        for one_hot, values in zip(encrypted_input, class_likelihoods):
            for bit, value in zip(one_hot, values):
                if value % u != 0:
                    score = cs.add(score, cs.multiply_by_constant(bit, value % u))
        scores.append(score)
    return cs.evaluate_argmax(encrypted_values=scores, bit_length=bit_length, client=client)


def validate_model_shape(
    weights: Optional[List[List[int]]] = None,
    likelihoods: Optional[List[List[List[float]]]] = None,
) -> None:
    """
    Check that every class of a model has the same shape
    """
    if weights is not None:
        if not isinstance(weights, list) or len(weights) == 0:
            raise ValueError("Weights must be a non-empty list of class weights")
        if any(not isinstance(w, list) or len(w) != len(weights[0]) for w in weights):
            raise ValueError("Every class must have the same number of weights")
    if likelihoods is not None:
        if not isinstance(likelihoods, list) or len(likelihoods) == 0:
            raise ValueError("Likelihoods must be a non-empty list of class likelihoods")
        shape = [len(values) for values in likelihoods[0]]
        if any([len(values) for values in c] != shape for c in likelihoods):
            raise ValueError("Every class must have likelihoods of the same features and values")
