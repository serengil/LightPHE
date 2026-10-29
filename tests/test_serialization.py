import json
import random

import pytest

from lightphe import LightPHE
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.CatalanoFiore import CatalanoFioreCiphertext
from lightphe.models.Tensor import EncryptedTensor
from lightphe.commons import serialization
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_serialization.py")

# small keys are not secure, and are for testing only
ALGORITHMS = [
    ("RSA", {"key_size": 128}, "mul"),
    ("ElGamal", {"key_size": 128}, "mul"),
    ("Exponential-ElGamal", {"key_size": 128}, "add"),
    ("EllipticCurve-ElGamal", {}, "add"),
    ("Paillier", {"key_size": 128}, "add"),
    ("Damgard-Jurik", {"key_size": 128}, "add"),
    ("Okamoto-Uchiyama", {"key_size": 128}, "add"),
    ("Benaloh", {"key_size": 64}, "add"),
    ("Naccache-Stern", {"key_size": 64}, "add"),
    ("Goldwasser-Micali", {"key_size": 64}, "xor"),
    ("Sander-Young-Yung", {"key_size": 64}, "and"),
    ("Boneh-Goh-Nissim", {"key_size": 64}, "add"),
    ("Joye-Libert", {"key_size": 128}, "add"),
    ("Castagnos-Laguillaumie", {"key_size": 128}, "add"),
    ("Ishai-Paskin", {"key_size": 128}, "add"),
    ("Damgard-Geisler-Kroigaard", {"key_size": 128}, "add"),
    ("Bresson-Catalano-Pointcheval", {"key_size": 128}, "add"),
    ("Camenisch-Shoup", {"key_size": 128}, "add"),
    ("EllipticCurve-Paillier", {"key_size": 128}, "add"),
    ("Regev", {}, "add"),
    ("Brakerski-Vaikuntanathan", {"key_size": 64}, "add"),
    ("Freeman-Boneh-Goh-Nissim", {}, "add"),
    ("Gentry-Halevi-Vaikuntanathan", {}, "add"),
    ("Lyubashevsky-Peikert-Regev", {"key_size": 64}, "add"),
    ("ML-KEM", {"key_size": 512}, "xor"),
    ("Gentry-Sahai-Waters", {"key_size": 64}, "xor"),
]


def public_party(cs: LightPHE) -> LightPHE:
    return LightPHE(
        algorithm_name=cs.algorithm_name,
        keys={"public_key": cs.cs.keys["public_key"]},
        form=cs.form,
        curve=cs.curve,
    )


@pytest.mark.parametrize("algorithm_name, kwargs, operation", ALGORITHMS)
def test_round_trip_through_untrusted_party(algorithm_name, kwargs, operation):
    owner = LightPHE(algorithm_name=algorithm_name, **kwargs)
    cloud = public_party(owner)

    m1, m2 = 1, 1
    c1, c2 = owner.encrypt(m1), owner.encrypt(m2)

    # owner sends ciphertexts, and cloud computes on them with the public key only
    data = owner.serialize(c1)
    assert "private_key" not in data
    restored1 = cloud.deserialize(data)
    restored2 = cloud.from_dict(json.loads(json.dumps(c2.to_dict())))
    assert isinstance(restored1, Ciphertext)
    assert restored1.value == c1.value
    assert type(restored1.value) is type(c1.value)
    assert restored1.cs.keys.get("private_key") is None

    if operation == "mul":
        result, expected = restored1 * restored2, m1 * m2
    elif operation == "xor":
        result, expected = restored1 ^ restored2, m1 ^ m2
    elif operation == "and":
        result, expected = restored1 & restored2, m1 & m2
    else:
        result, expected = restored1 + restored2, m1 + m2

    # cloud sends the result back to the owner
    decrypted = owner.decrypt(owner.deserialize(cloud.serialize(result)))
    assert decrypted in [expected, [expected]]

    logger.info(f"✅ Serialization round trip test succeeded for {algorithm_name}")


@pytest.mark.parametrize(
    "algorithm_name, kwargs",
    [
        ("Boneh-Goh-Nissim", {"key_size": 64}),
        ("Freeman-Boneh-Goh-Nissim", {}),
        ("Brakerski-Vaikuntanathan", {"key_size": 64}),
    ],
)
def test_multiplied_ciphertexts(algorithm_name, kwargs):
    # multiplied ciphertexts of these algorithms are told apart by their types,
    # e.g. a point on the curve for Boneh-Goh-Nissim becomes a tuple in F_p^2
    owner = LightPHE(algorithm_name=algorithm_name, **kwargs)
    cloud = public_party(owner)

    c1, c2 = cloud.deserialize(owner.serialize(owner.encrypt(3))), owner.encrypt(4)
    product = c1 * cloud.from_dict(c2.to_dict())
    restored = owner.deserialize(cloud.serialize(product))
    assert type(restored.value) is type(product.value)
    assert owner.decrypt(restored) == 12

    logger.info(f"✅ Multiplied ciphertext serialization test succeeded for {algorithm_name}")


def test_structures_are_preserved():
    cs = LightPHE(algorithm_name="Paillier", key_size=128)
    c = cs.encrypt(5)
    item = {
        "tuple": (1, (2, 3), [4]),
        "list": [c, None, True, "text", 1.5],
        "int_keys": {1: c, 2: (c, c)},
        "inf": (float("inf"), float("-inf")),
        serialization.TAG: "not an encoded object",
    }
    restored = cs.deserialize(cs.serialize(item))

    assert restored["tuple"] == (1, (2, 3), [4])
    assert isinstance(restored["tuple"][1], tuple) and isinstance(restored["tuple"][2], list)
    assert restored["list"][1:] == [None, True, "text", 1.5]
    assert cs.decrypt(restored["list"][0]) == 5
    assert list(restored["int_keys"].keys()) == [1, 2]
    assert isinstance(restored["int_keys"][2], tuple)
    assert cs.decrypt(restored["int_keys"][2][1]) == 5
    assert restored["inf"] == (float("inf"), float("-inf"))
    assert restored[serialization.TAG] == "not an encoded object"

    logger.info("✅ Serialization preserves tuples, dict keys and floats")


def test_tensors():
    cs = LightPHE(algorithm_name="Paillier", key_size=128, precision=3)
    cloud = public_party(cs)
    signed = cs.deserialize(cs.serialize(cs.encrypt([1.5, -2.25, 3], silent=True)))
    assert cs.decrypt(signed) == pytest.approx([1.5, -2.25, 3])

    restored = cloud.deserialize(cs.serialize(cs.encrypt([1.5, 2.25, 3], silent=True)))
    assert isinstance(restored, EncryptedTensor)
    assert restored.cs.keys.get("private_key") is None

    # cloud multiplies the encrypted tensor with a plain tensor and sends it back
    result = cs.deserialize(cloud.serialize(restored * [2, 2, 2]))
    assert cs.decrypt(result) == pytest.approx([3, 4.5, 6])

    logger.info("✅ Encrypted tensor serialization test succeeded")


def test_proofs():
    prover = LightPHE(algorithm_name="Paillier", key_size=128)
    verifier = public_party(prover)

    ciphertext, proof = prover.encrypt_with_range_proof(17, low=0, high=100)
    received_ciphertext, received_proof = verifier.deserialize(
        prover.serialize((ciphertext, proof))
    )
    assert verifier.verify_range(received_ciphertext, received_proof, low=0, high=100)

    ciphertexts, proof = prover.encrypt_one_hot(choice=1, options=3)
    received_ciphertexts, received_proof = verifier.deserialize(
        prover.serialize((ciphertexts, proof))
    )
    assert verifier.verify_one_hot(received_ciphertexts, received_proof)

    plaintext, proof = prover.decrypt_with_proof(ciphertext)
    data = prover.serialize({"ciphertext": ciphertext, "plaintext": plaintext, "proof": proof})
    message = verifier.deserialize(data)
    assert verifier.verify_decryption(message["ciphertext"], message["plaintext"], message["proof"])

    logger.info("✅ Proof serialization test succeeded")


def test_elliptic_curve_proofs():
    prover = LightPHE(algorithm_name="EllipticCurve-ElGamal")
    verifier = public_party(prover)

    ciphertext = prover.encrypt(7)
    plaintext, proof = prover.decrypt_with_proof(ciphertext)
    message = verifier.deserialize(prover.serialize([ciphertext, plaintext, proof]))
    assert verifier.verify_decryption(*message)

    logger.info("✅ Elliptic curve proof serialization test succeeded")


def test_threshold_decryption_over_network():
    dealer = LightPHE(algorithm_name="Paillier", key_size=256, safe_primes=True)
    share_keys = dealer.generate_threshold_keys(threshold=2, parties=3)
    shareholders = [LightPHE(algorithm_name="Paillier", keys=keys) for keys in share_keys]
    combiner = public_party(dealer)

    ciphertext = combiner.encrypt(42)
    data = combiner.serialize(ciphertext)

    # every shareholder receives the ciphertext, and sends its partial decryption back
    partials = [
        combiner.deserialize(
            shareholder.serialize(
                shareholder.partial_decrypt(shareholder.deserialize(data), prove=True)
            )
        )
        for shareholder in shareholders[:2]
    ]
    assert combiner.combine_partial_decryptions(ciphertext, partials, verify=True) == 42

    logger.info("✅ Threshold decryption over network test succeeded")


def test_secure_aggregation_over_network():
    random.seed(3)
    owner = LightPHE(algorithm_name="Paillier", key_size=256)
    server = public_party(owner)
    clients = [public_party(owner) for _ in range(3)]
    updates = [[random.uniform(-1, 1) for _ in range(20)] for _ in clients]

    messages = [
        client.serialize(client.encrypt_update(update, max_value=1, max_clients=10))
        for client, update in zip(clients, updates)
    ]
    encrypted_sum = server.aggregate_updates([server.deserialize(m) for m in messages])
    result = owner.decrypt_aggregate(owner.deserialize(server.serialize(encrypted_sum)))

    expected = [sum(update[i] for update in updates) for i in range(20)]
    assert result["count"] == 3
    assert result["sum"] == pytest.approx(expected, abs=1e-4)

    logger.info("✅ Secure aggregation over network test succeeded")


def test_knn_over_network():
    client = LightPHE(algorithm_name="Damgard-Geisler-Kroigaard", key_size=512)
    server = public_party(client)

    def network(message: dict) -> list:
        # server serializes its message, client answers it, and server restores the answer
        answer = client.answer_knn(client.deserialize(server.serialize(message)))
        return server.deserialize(client.serialize(answer))

    database = [[1, 2], [5, 5], [0, 0], [9, 1]]
    query = server.deserialize(client.serialize(client.encrypt_knn_query([1, 1])))
    result = server.evaluate_knn(query, database, k=2, bit_length=8, client=network)
    received = client.deserialize(server.serialize(result))

    assert [client.decrypt(c) for c in received["indices"]] == [0, 2]

    logger.info("✅ k-NN over network test succeeded")


def test_catalano_fiore():
    owner = LightPHE(algorithm_name="Paillier", key_size=128, boost="Catalano-Fiore")
    cloud = LightPHE(
        algorithm_name="Paillier",
        keys={"public_key": owner.cs.keys["public_key"]},
        boost="Catalano-Fiore",
    )

    database = [[1, 2, 3], [4, 4, 4], [0, 1, 2]]
    query = [1, 1, 1]
    encrypted_database = cloud.deserialize(
        owner.serialize([[owner.encrypt(x) for x in vector] for vector in database])
    )
    encrypted_query = cloud.from_dict(json.loads(owner.serialize([owner.encrypt(x) for x in query])))
    assert all(isinstance(c, CatalanoFioreCiphertext) for c in encrypted_query)

    distances = cloud.evaluate_knn_distances(encrypted_query, encrypted_database)
    received = owner.deserialize(cloud.serialize(distances))
    assert all(c.is_multiplied for c in received)
    assert owner.decrypt_knn(received, k=2) == {"indices": [2, 0], "distances": [2, 5]}

    # a party without the boost restores Catalano-Fiore ciphertexts as well
    product = public_party(owner).from_dict((owner.encrypt(6) * owner.encrypt(7)).to_dict())
    assert isinstance(product, CatalanoFioreCiphertext) and product.is_multiplied
    assert owner.decrypt(product) == 42

    logger.info("✅ Catalano-Fiore serialization test succeeded")


def test_invalid_inputs():
    cs = LightPHE(algorithm_name="Paillier", key_size=128)
    data = cs.encrypt(5).to_dict()

    other = LightPHE(algorithm_name="Damgard-Jurik", key_size=128)
    with pytest.raises(ValueError, match="belongs to Paillier"):
        other.from_dict(data)

    with pytest.raises(ValueError, match="not a valid json"):
        cs.deserialize("{not json")

    for value in ["123", True, None, {"x": 1}, [1, "2"], 1.5]:
        with pytest.raises(ValueError, match="must consist of integers"):
            cs.from_dict({**data, "value": value})

    with pytest.raises(ValueError, match="version"):
        cs.from_dict({**data, "version": 999})
    with pytest.raises(ValueError, match="Unknown serialized object"):
        cs.from_dict({serialization.TAG: "something"})
    with pytest.raises(ValueError, match="Invalid encoded float"):
        cs.from_dict({serialization.TAG: "float", "value": "1e3"})
    with pytest.raises(ValueError, match="cannot be serialized"):
        cs.serialize(object())

    # points must be on the curve
    bgn = LightPHE(algorithm_name="Boneh-Goh-Nissim", key_size=64)
    point_data = bgn.encrypt(1).to_dict()
    point_data["value"]["y"] += 1
    with pytest.raises(ValueError, match="not on the curve"):
        bgn.from_dict(point_data)
    with pytest.raises(ValueError, match="not elliptic curve points"):
        cs.from_dict({**data, "value": point_data["value"]})

    # Catalano-Fiore ciphertexts must be well formed
    cf = LightPHE(algorithm_name="Paillier", keys=cs.cs.keys, boost="Catalano-Fiore")
    cf_data = cf.encrypt(5).to_dict()
    modulo = cs.cs.plaintext_modulo
    with pytest.raises(ValueError, match="must be in"):
        cs.from_dict({**cf_data, "a": modulo})
    with pytest.raises(ValueError, match="a and beta only"):
        cs.from_dict({**cf_data, "pairs": [[data, data]]})
    with pytest.raises(ValueError, match="alpha and pairs only"):
        cs.from_dict({**cf_data, "alpha": data})
    with pytest.raises(ValueError, match="belongs to Paillier"):
        other.from_dict(cf_data)

    logger.info("✅ Invalid serialized inputs are rejected")
