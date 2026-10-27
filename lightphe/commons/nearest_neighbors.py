# built-in dependencies
import random
from typing import Any, Callable, Dict, List, Optional

# Encrypted k nearest neighbor search. Client (private key owner) encrypts a query vector,
# and server finds the k nearest vectors of its database by squared euclidean distance
# without learning the query, the distances or the result. Client learns only the indices,
# or the labels, of the k nearest vectors in order.
#   - distance: ||q - x||^2 = ||q||^2 - 2 <q, x> + ||x||^2 is linear in the encrypted q when
#       client sends E(||q||^2) as well, so server computes it with additions and
#       multiplications with constants only.
#   - argmin: argmax of 2^bit_length - 1 - distance with the interactive argmax of
#       Damgard-Geisler-Kroigaard, which reveals nothing to both parties.
#   - exclusion: server turns the encrypted index of the nearest vector into an encrypted
#       one-hot vector with the client's help, and lifts every other value by 2^bit_length,
#       so the next argmax finds the next nearest vector.
# Ref: Erkin, Z. et al. (2009). Privacy-Preserving Face Recognition. PETS 2009.

# pylint: disable=too-many-arguments, too-many-locals


def encrypt_query(cs: Any, query: List[int]) -> Dict[str, Any]:
    """
    Encrypt a query vector and its squared norm. Runs on client side.
    Args:
        cs (Homomorphic): additively homomorphic cryptosystem
        query (list of int): query vector
    Returns:
        encrypted query (dict): ciphertexts of entries and of the squared norm
    """
    u = cs.plaintext_modulo
    return {
        "query": [cs.encrypt(plaintext=x % u) for x in query],
        "norm": cs.encrypt(plaintext=sum(x * x for x in query) % u),
    }


def evaluate_knn(
    cs: Any,
    encrypted_query: Dict[str, Any],
    database: List[List[int]],
    k: int,
    bit_length: int,
    client: Callable[[dict], List[int]],
    labels: Optional[List[int]] = None,
) -> Dict[str, List[Any]]:
    """
    Find the k nearest vectors of a database to an encrypted query. Runs on server side
        and interacts with the client through the client callable.
    Args:
        cs (Homomorphic): Damgard-Geisler-Kroigaard cryptosystem having the public key
        encrypted_query (dict): output of encrypt_query
        database (list of list of int): vectors of the server
        k (int): number of nearest vectors to find
        bit_length (int): squared distances must be less than 2^bit_length
        client (callable): sends a message to the client and returns its response
        labels (list of int): optional labels of vectors. If set, encrypted labels of the
            nearest vectors are returned as well.
    Returns:
        result (dict): encrypted indices, and encrypted labels if labels are set,
            of the k nearest vectors from the nearest one
    """
    u = cs.plaintext_modulo
    size = len(database)
    offset = 1 << bit_length

    query = encrypted_query["query"]
    norm = encrypted_query["norm"]

    # values = 2^bit_length - 1 - distance, so the nearest vector has the greatest value
    values = []
    for vector in database:
        value = cs.add(
            cs.encrypt(plaintext=(offset - 1 - sum(x * x for x in vector)) % u),
            cs.multiply_by_constant(norm, u - 1),
        )
        for x, encrypted_q in zip(vector, query):
            if x % u != 0:
                value = cs.add(value, cs.multiply_by_constant(encrypted_q, (2 * x) % u))
        values.append(value)

    # values are lifted by 2^bit_length in each round, so they need more bits
    argmax_bit_length = bit_length + k.bit_length()

    indices: List[Any] = []
    found_labels: List[Any] = []
    for round_index in range(k):
        index = cs.evaluate_argmax(
            encrypted_values=values, bit_length=argmax_bit_length, client=client
        )
        indices.append(index)

        last_round = round_index == k - 1
        if last_round and labels is None:
            break

        one_hot = one_hot_index(cs=cs, encrypted_index=index, size=size, client=client)

        if labels is not None:
            label = cs.encrypt(plaintext=0)
            for bit, plain_label in zip(one_hot, labels):
                if plain_label % u != 0:
                    label = cs.add(label, cs.multiply_by_constant(bit, plain_label % u))
            found_labels.append(cs.reencrypt(label))

        if not last_round:
            # every value except the found one is lifted by 2^bit_length: value + offset (1 - bit)
            lift = cs.encrypt(plaintext=offset % u)
            values = [
                cs.add(cs.add(value, lift), cs.multiply_by_constant(bit, (u - offset) % u))
                for value, bit in zip(values, one_hot)
            ]

    result: Dict[str, List[Any]] = {"indices": indices}
    if labels is not None:
        result["labels"] = found_labels
    return result


def one_hot_index(
    cs: Any, encrypted_index: Any, size: int, client: Callable[[dict], List[int]]
) -> List[Any]:
    """
    Turn an encrypted index into an encrypted one-hot vector with the client's help.
        Client receives E(r_i (index - i)) for random non-zero r_i in a random order, so
        it learns only that one of them is zero, but not its position.
    Args:
        cs (Homomorphic): Damgard-Geisler-Kroigaard cryptosystem having the public key
        encrypted_index (ciphertext): encrypted index in [0, size)
        size (int): length of the one-hot vector
        client (callable): sends a message to the client and returns its response
    Returns:
        one-hot vector (list of ciphertexts): E(1) at the index, and E(0) elsewhere
    """
    u = cs.plaintext_modulo
    order = list(range(size))
    random.shuffle(order)

    blinded = []
    for i in order:
        difference = cs.add(encrypted_index, cs.encrypt(plaintext=(-i) % u))
        blinded.append(cs.reencrypt(cs.multiply_by_constant(difference, random.randint(1, u - 1))))

    bits = client({"type": "equality", "payload": blinded})

    one_hot: List[Any] = [None] * size
    for i, bit in zip(order, bits):
        one_hot[i] = bit
    return one_hot


def answer_knn(cs: Any, message: dict) -> List[int]:
    """
    Answer a message of the server during encrypted nearest neighbor search. Runs on
        client side. Messages of argmax are answered by the cryptosystem's answer_argmax.
    Args:
        cs (Homomorphic): Damgard-Geisler-Kroigaard cryptosystem having the private key
        message (dict): message of the server having type and payload keys
    Returns:
        response (list of int): ciphertexts to be sent back to the server
    """
    if message.get("type") == "equality":
        return [cs.encrypt(plaintext=int(cs.is_zero(c))) for c in message.get("payload")]
    return cs.answer_argmax(message)
