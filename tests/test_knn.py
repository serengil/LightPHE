import random

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_knn.py")

# 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
# they are not secure, and are for testing only.
client_cs = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=512)
server_cs = LightPHE(
    algorithm_name="Damgard-Geisler-Kroigaard",
    keys={"public_key": client_cs.cs.keys["public_key"]},
)


def plain_knn(query, database, k):
    distances = [sum((a - b) ** 2 for a, b in zip(query, vector)) for vector in database]
    # earlier index first on ties
    return sorted(range(len(database)), key=lambda i: (distances[i], i))[:k]


def search(query, database, k, bit_length, labels=None, client=None):
    encrypted_query = client_cs.encrypt_knn_query(query)
    result = server_cs.evaluate_knn(
        encrypted_query,
        database,
        k=k,
        bit_length=bit_length,
        client=client or client_cs.answer_knn,
        labels=labels,
    )
    indices = [client_cs.decrypt(c) for c in result["indices"]]
    decrypted_labels = [client_cs.decrypt(c) for c in result.get("labels", [])]
    return indices, decrypted_labels


def test_matches_plain_knn():
    random.seed(7)
    for _ in range(2):
        database = [[random.randint(-50, 50) for _ in range(8)] for _ in range(10)]
        labels = [random.randint(1, 10**6) for _ in database]
        query = [random.randint(-50, 50) for _ in range(8)]

        indices, found_labels = search(query, database, k=3, bit_length=17, labels=labels)
        expected = plain_knn(query, database, k=3)
        assert indices == expected
        assert found_labels == [labels[i] for i in expected]

    logger.info("✅ Encrypted k-NN matches plain k-NN")


def test_k_of_one_and_full_ranking():
    random.seed(11)
    database = [[random.randint(0, 20) for _ in range(4)] for _ in range(5)]
    query = [random.randint(0, 20) for _ in range(4)]

    indices, labels = search(query, database, k=1, bit_length=12)
    assert indices == plain_knn(query, database, k=1)
    assert labels == []

    indices, _ = search(query, database, k=5, bit_length=12)
    assert indices == plain_knn(query, database, k=5)


def test_ties_return_earlier_index_first():
    database = [[3, 4], [0, 0], [3, 4], [0, 0], [9, 9]]
    indices, _ = search([0, 0], database, k=4, bit_length=8)
    assert indices == [1, 3, 0, 2]


def test_client_sees_one_zero_in_shuffled_positions():
    database = [[i, 2 * i] for i in range(6)]
    seen = []

    def recording_client(message):
        if message["type"] == "equality":
            decrypted = [client_cs.cs.is_zero(c) for c in message["payload"]]
            seen.append(decrypted)
        return client_cs.answer_knn(message)

    random.seed(3)
    indices, _ = search([0, 0], database, k=3, bit_length=8, client=recording_client)
    assert indices == [0, 1, 2]

    # one equality round per found vector except the last one, each having a single zero
    assert len(seen) == 2
    assert all(sum(round_) == 1 and len(round_) == len(database) for round_ in seen)


def test_face_search_with_quantized_embeddings():
    # gallery of 8 people with 32-dimensional embeddings in [-1, 1]
    random.seed(5)
    gallery = [[random.uniform(-1, 1) for _ in range(32)] for _ in range(8)]
    people = [101, 102, 103, 104, 105, 106, 107, 108]

    # query is a noisy capture of person 105
    query = [x + random.gauss(0, 0.05) for x in gallery[4]]

    # embeddings are quantized to 8-bit integers, so squared distances are less than 2^21
    def quantize(vector):
        return [max(-127, min(127, round(x * 127))) for x in vector]

    _, labels = search(
        quantize(query), [quantize(v) for v in gallery], k=1, bit_length=21, labels=people
    )
    assert labels == [105]


def test_invalid_inputs():
    encrypted_query = client_cs.encrypt_knn_query([1, 2])
    database = [[1, 2], [3, 4]]

    with pytest.raises(ValueError, match="list of 2 integers"):
        server_cs.evaluate_knn(encrypted_query, [[1, 2, 3]], 1, 8, client_cs.answer_knn)
    with pytest.raises(ValueError, match="list of 2 integers"):
        server_cs.evaluate_knn(encrypted_query, [[1, 2.5]], 1, 8, client_cs.answer_knn)
    for k in [0, 3]:
        with pytest.raises(ValueError, match="k must be in"):
            server_cs.evaluate_knn(encrypted_query, database, k, 8, client_cs.answer_knn)
    with pytest.raises(ValueError, match="one for each vector"):
        server_cs.evaluate_knn(encrypted_query, database, 1, 8, client_cs.answer_knn, labels=[1])
    with pytest.raises(ValueError, match="does not fit"):
        server_cs.evaluate_knn(encrypted_query, database, 1, 4, client_cs.answer_knn)
    with pytest.raises(ValueError, match="too small for argmax"):
        server_cs.evaluate_knn(encrypted_query, database, 1, 40, client_cs.answer_knn)
    with pytest.raises(ValueError, match="output of encrypt_knn_query"):
        server_cs.evaluate_knn({}, database, 1, 8, client_cs.answer_knn)
    with pytest.raises(ValueError, match="non-empty list of integers"):
        client_cs.encrypt_knn_query([1.5, 2])
    with pytest.raises(ValueError, match="private key"):
        server_cs.answer_knn({"type": "equality", "payload": []})

    paillier = LightPHE(algorithm_name="Paillier", key_size=64)
    with pytest.raises(ValueError, match="does not support encrypted nearest neighbor search"):
        paillier.encrypt_knn_query([1, 2])


# scenario b: owner stores its encrypted database in an untrusted cloud
owner_cs = LightPHE(algorithm_name="Paillier", key_size=256, boost="Catalano-Fiore")
cloud_cs = LightPHE(
    algorithm_name="Paillier",
    keys={"public_key": owner_cs.cs.keys["public_key"]},
    boost="Catalano-Fiore",
)


def test_encrypted_database_in_cloud():
    random.seed(13)
    database = [[random.randint(-100, 100) for _ in range(6)] for _ in range(8)]
    query = [random.randint(-100, 100) for _ in range(6)]

    # owner encrypts its database once and uploads it, then encrypts queries
    encrypted_database = [[owner_cs.encrypt(x) for x in vector] for vector in database]
    encrypted_query = [owner_cs.encrypt(x) for x in query]

    # cloud computes encrypted distances with the public key only
    encrypted_distances = cloud_cs.evaluate_knn_distances(encrypted_query, encrypted_database)
    assert len(encrypted_distances) == len(database)
    with pytest.raises(ValueError, match="private key"):
        cloud_cs.decrypt_knn(encrypted_distances, k=3)

    # owner decrypts them and finds the nearest vectors locally
    result = owner_cs.decrypt_knn(encrypted_distances, k=3)
    expected = plain_knn(query, database, k=3)
    assert result["indices"] == expected
    assert result["distances"] == [
        sum((a - b) ** 2 for a, b in zip(query, database[i])) for i in expected
    ]

    logger.info("✅ Encrypted database in cloud test succeeded")


def test_encrypted_database_in_cloud_invalid_inputs():
    encrypted_query = [owner_cs.encrypt(x) for x in [1, 2]]
    encrypted_database = [[owner_cs.encrypt(x) for x in [3, 4]]]

    with pytest.raises(ValueError, match="list of 2 encrypted integers"):
        cloud_cs.evaluate_knn_distances(encrypted_query, [[owner_cs.encrypt(1)]])
    with pytest.raises(ValueError, match="non-empty list of encrypted integers"):
        cloud_cs.evaluate_knn_distances([1, 2], encrypted_database)

    # products cannot be multiplied again
    product = encrypted_query[0] * encrypted_query[1]
    with pytest.raises(ValueError, match="non-empty list of encrypted integers"):
        cloud_cs.evaluate_knn_distances([product, encrypted_query[1]], encrypted_database)

    distances = cloud_cs.evaluate_knn_distances(encrypted_query, encrypted_database)
    for k in [0, 2]:
        with pytest.raises(ValueError, match="k must be in"):
            owner_cs.decrypt_knn(distances, k=k)

    with pytest.raises(ValueError, match="boost='Catalano-Fiore'"):
        LightPHE(algorithm_name="Paillier", key_size=64).evaluate_knn_distances(
            encrypted_query, encrypted_database
        )
