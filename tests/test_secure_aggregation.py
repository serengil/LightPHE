import random

import pytest

from lightphe import LightPHE
from lightphe.commons import secure_aggregation
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_secure_aggregation.py")

# quantization error of a value is at most half of 10^-precision
PRECISION = 5
TOLERANCE = 10**-PRECISION


def build_committee(algorithm_name="Paillier", threshold=3, parties=5):
    """
    Dealer splits the key among a committee, and the server has the public key only
    """
    dealer = LightPHE(algorithm_name=algorithm_name, key_size=256, safe_primes=True)
    share_keys = dealer.generate_threshold_keys(threshold=threshold, parties=parties)
    committee = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]
    server = LightPHE(
        algorithm_name=algorithm_name, keys={"public_key": dealer.cs.keys["public_key"]}
    )
    return server, committee


def test_packing_round_trip():
    modulo = 2**1024
    layout = secure_aggregation.build_layout(
        length=100, precision=3, max_value=2.5, max_clients=7, modulo=modulo
    )
    assert layout["bound"] == 2500
    assert layout["slot_bits"] == (7 * 2 * 2500).bit_length()
    assert layout["slots"] == (modulo.bit_length() - 1) // layout["slot_bits"]

    updates = [[round(random.uniform(-2.5, 2.5), 3) for _ in range(100)] for _ in range(7)]
    updates[0][:3] = [2.5, -2.5, 0]

    # sum of packed plaintexts unpacks to the sum of updates, as slots never overflow
    total = [0] * secure_aggregation.chunks_of(layout)
    for update in updates:
        for i, plaintext in enumerate(secure_aggregation.pack(update, layout)):
            assert plaintext < modulo
            total[i] += plaintext
    restored = secure_aggregation.unpack(total, layout, count=7)
    expected = [sum(update[i] for update in updates) for i in range(100)]
    assert restored == pytest.approx(expected, abs=1e-9)


def test_threshold_aggregation():
    random.seed(1)
    server, committee = build_committee()
    length = 120
    updates = [[random.uniform(-1, 1) for _ in range(length)] for _ in range(6)]

    encrypted = [server.encrypt_update(update, max_value=1, max_clients=50) for update in updates]
    layout = encrypted[0]["layout"]
    assert len(encrypted[0]["chunks"]) == secure_aggregation.chunks_of(layout) < length

    encrypted_sum = server.aggregate_updates(encrypted)
    assert encrypted_sum["count"] == 6

    # any 3 of 5 members decrypt the sum, e.g. if 2 members drop out
    partials = [member.partial_decrypt_aggregate(encrypted_sum, prove=True) for member in committee]
    for subset in [partials[:3], partials[2:]]:
        result = server.combine_aggregate(encrypted_sum, subset, verify=True)
        expected_sum = [sum(update[i] for update in updates) for i in range(length)]
        assert result["count"] == 6
        assert result["sum"] == pytest.approx(expected_sum, abs=6 * TOLERANCE)
        assert result["mean"] == pytest.approx([x / 6 for x in expected_sum], abs=TOLERANCE)

    # 2 members cannot decrypt the sum
    with pytest.raises(ValueError, match="At least 3"):
        server.combine_aggregate(encrypted_sum, partials[:2])

    logger.info("✅ Threshold secure aggregation test succeeded")


def test_cheating_committee_member_is_discarded():
    random.seed(2)
    server, committee = build_committee()
    updates = [[random.uniform(-1, 1) for _ in range(10)] for _ in range(3)]
    encrypted_sum = server.aggregate_updates(
        [server.encrypt_update(update, max_value=1, max_clients=10) for update in updates]
    )
    partials = [member.partial_decrypt_aggregate(encrypted_sum, prove=True) for member in committee[:4]]

    # member 1 shifts its partial decryption of the first chunk to bias the sum
    n = server.cs.keys["public_key"]["n"]
    modulo = server.cs.ciphertext_modulo
    forged = dict(partials[0][0])
    forged["value"] = (forged["value"] * (1 + n)) % modulo
    partials[0] = [forged] + partials[0][1:]

    # without verification, the sum is wrong
    expected_sum = [sum(update[i] for update in updates) for i in range(10)]
    biased = server.combine_aggregate(encrypted_sum, partials[:3])
    assert biased["sum"] != pytest.approx(expected_sum, abs=3 * TOLERANCE)

    # with verification, the forged partial decryption is discarded
    result = server.combine_aggregate(encrypted_sum, partials, verify=True)
    assert result["sum"] == pytest.approx(expected_sum, abs=3 * TOLERANCE)


def test_federated_averaging():
    """
    Clients train a linear model y = w x + b on their private data. In each round, each
    client sends its encrypted weights, and the committee decrypts only their average.
    """
    random.seed(3)
    server, committee = build_committee(threshold=2, parties=3)

    true_w, true_b = 2.0, -1.0
    clients = []
    for _ in range(4):
        xs = [random.uniform(-1, 1) for _ in range(30)]
        ys = [true_w * x + true_b + random.gauss(0, 0.01) for x in xs]
        clients.append((xs, ys))

    weights = [0.0, 0.0]
    for _ in range(30):
        updates = []
        for xs, ys in clients:
            # one local step of gradient descent on mean squared error
            w, b = weights
            grad_w = sum(2 * (w * x + b - y) * x for x, y in zip(xs, ys)) / len(xs)
            grad_b = sum(2 * (w * x + b - y) for x, y in zip(xs, ys)) / len(xs)
            updates.append([w - 0.5 * grad_w, b - 0.5 * grad_b])

        encrypted_sum = server.aggregate_updates(
            [server.encrypt_update(update, max_value=10, max_clients=4) for update in updates]
        )
        partials = [member.partial_decrypt_aggregate(encrypted_sum) for member in committee[:2]]
        weights = server.combine_aggregate(encrypted_sum, partials)["mean"]

    assert weights == pytest.approx([true_w, true_b], abs=0.05)


def test_single_key_owner_and_damgard_jurik():
    for algorithm_name in ["Paillier", "Damgard-Jurik"]:
        cs = LightPHE(algorithm_name=algorithm_name, key_size=256)
        updates = [[0.5, -0.25, 1.0], [-1.0, 0.75, 0.0]]
        encrypted_sum = cs.aggregate_updates(
            [cs.encrypt_update(update, max_value=1, max_clients=2) for update in updates]
        )
        result = cs.decrypt_aggregate(encrypted_sum)
        assert result["sum"] == pytest.approx([-0.5, 0.5, 1.0])
        assert result["mean"] == pytest.approx([-0.25, 0.25, 0.5])


def test_invalid_inputs():
    cs = LightPHE(algorithm_name="Paillier", key_size=256)

    with pytest.raises(ValueError, match="exceeds the maximum value"):
        cs.encrypt_update([0.5, 1.5], max_value=1, max_clients=2)
    with pytest.raises(ValueError, match="list of numbers"):
        cs.encrypt_update([0.5, "a"], max_value=1, max_clients=2)
    with pytest.raises(ValueError, match="at least one value"):
        cs.encrypt_update([], max_value=1, max_clients=2)
    # a single slot needs more bits than the plaintext space of a 256-bit key has
    with pytest.raises(ValueError, match="too small"):
        cs.encrypt_update([0.5], max_value=10**80, max_clients=2)

    a = cs.encrypt_update([0.5, 0.5], max_value=1, max_clients=2)
    b = cs.encrypt_update([0.5], max_value=1, max_clients=2)
    with pytest.raises(ValueError, match="same layout"):
        cs.aggregate_updates([a, b])

    # summing more updates than the slots are packed for would overflow
    with pytest.raises(ValueError, match="overflow"):
        cs.aggregate_updates([a, a, a])

    with pytest.raises(ValueError, match="does not support secure aggregation"):
        LightPHE(algorithm_name="Exponential-ElGamal", key_size=50).encrypt_update(
            [0.5], max_value=1, max_clients=2
        )
