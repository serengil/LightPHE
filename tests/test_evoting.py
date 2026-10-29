import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_evoting.py")

# algorithm name, key size and keyword arguments. ElGamal variants need prime_order for
# proofs, Paillier and Damgard-Jurik need safe_primes for proofs of partial decryptions
ALL_ALGORITHMS = [
    ("Exponential-ElGamal", 128, {"prime_order": True}),
    ("EllipticCurve-ElGamal", None, {}),
    ("Paillier", 128, {"safe_primes": True}),
    ("Damgard-Jurik", 128, {"safe_primes": True}),
]

# a party election encodes votes as base^k, so the tally is a large number. ElGamal
# variants decrypt with a discrete logarithm, so only small tallies are feasible there.
LARGE_PLAINTEXT_ALGORITHMS = [
    ("Paillier", 128, {"safe_primes": True}),
    ("Damgard-Jurik", 128, {"safe_primes": True}),
]


@pytest.mark.parametrize("algorithm_name,key_size,kwargs", ALL_ALGORITHMS)
def test_encrypted_voting(algorithm_name, key_size, kwargs):
    """
    Voters cast 0/1 ballots with proofs, invalid ballots are rejected, valid ones are
        tallied homomorphically, and trustees threshold-decrypt the tally with proofs
    """
    authority_cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, **kwargs)
    share_keys = authority_cs.generate_threshold_keys(threshold=2, parties=3)
    trustees = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]

    votes = {"alice": 1, "bob": 0, "carol": 1, "dave": 1}
    ballots = {
        voter: authority_cs.encrypt_with_proof(vote, context=voter) for voter, vote in votes.items()
    }

    # mallory copies alice's ballot
    ballots["mallory"] = ballots["alice"]

    valid = [
        ballot
        for voter, (ballot, proof) in ballots.items()
        if authority_cs.verify_ciphertext(ballot, proof, context=voter)
    ]
    assert len(valid) == len(votes)

    tally = valid[0]
    for ballot in valid[1:]:
        tally = tally + ballot

    partials = [trustee.partial_decrypt(tally, prove=True) for trustee in trustees[:2]]
    yes_votes = authority_cs.combine_partial_decryptions(tally, partials, verify=True)
    assert yes_votes == 3

    # each valid ballot is 0 or 1, so no votes are the rest of the valid ballots.
    # referendum passes with a simple majority of yes votes.
    no_votes = len(valid) - yes_votes
    assert no_votes == 1
    assert yes_votes > no_votes, "referendum is expected to pass"

    logger.info(f"✅ Encrypted voting test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name,key_size,kwargs", LARGE_PLAINTEXT_ALGORITHMS)
def test_encrypted_election_of_parties(algorithm_name, key_size, kwargs):
    """
    Voters cast a ballot for one of many parties with proofs. A vote for party k is
        encrypted as base^k, so the tally keeps the count of each party in a digit.
    """
    authority_cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, **kwargs)
    public_cs = LightPHE(
        algorithm_name=algorithm_name, keys={"public_key": authority_cs.cs.keys["public_key"]}
    )

    # a vote for party k is encrypted as base^k, i.e. 1 for red, 100 for green and
    # 10000 for blue. tally is the sum of these values, so each party's count is kept
    # in its own digit in base 100, i.e. its own pair of decimal digits.
    # base must be greater than the votes a party can get. e.g. 100 votes for red
    # would be 100 x 1 = 100, which carries into green's digit and is decoded as
    # 0 for red and 1 for green. so, a party can get at most 99 votes in base 100.
    # use a larger base for real elections, e.g. 1000001 for a million votes per party.
    # base^parties must also be less than the modulus n, otherwise the digit of the last
    # party wraps around. e.g. (10^6)^k < 2^1024 holds up to ~51 parties for a 1024-bit
    # key, and up to ~6 parties for the 128-bit key in this test. base does not change
    # the cost of encryption, decryption or proofs. proof size grows with the number of
    # parties instead. casting each ballot with its proof takes milliseconds, so a real
    # election with a million voters takes minutes, which is too slow for a unit test.
    parties = ["red", "green", "blue"]
    base = 100
    values = [base**k for k in range(len(parties))]

    votes = {"alice": "red", "bob": "blue", "carol": "red", "dave": "red", "erin": "blue"}
    ballots = {
        voter: public_cs.encrypt_with_proof(
            values[parties.index(party)], values=values, context=voter
        )
        for voter, party in votes.items()
    }

    # mallory copies alice's ballot
    ballots["mallory"] = ballots["alice"]

    # oscar cannot vote twice for a party, as 2 * base^k is not an allowed value
    with pytest.raises(ValueError, match="one of the allowed values"):
        public_cs.encrypt_with_proof(2 * values[1], values=values, context="oscar")

    # oscar cannot reuse a proof of a single vote for a doubled ballot
    oscar_ballot, oscar_proof = public_cs.encrypt_with_proof(values[1], values=values, context="oscar")
    ballots["oscar"] = (oscar_ballot + oscar_ballot, oscar_proof)

    valid = [
        ballot
        for voter, (ballot, proof) in ballots.items()
        if public_cs.verify_ciphertext(ballot, proof, values=values, context=voter)
    ]
    assert len(valid) == len(votes)

    tally = valid[0]
    for ballot in valid[1:]:
        tally = tally + ballot

    # authority decrypts the tally with a proof, and anyone verifies it
    result, proof = authority_cs.decrypt_with_proof(tally)
    assert public_cs.verify_decryption(tally, result, proof) is True

    # 3 x 1 + 0 x 100 + 2 x 10000 = 20003, which is read 2 digits at a time from right:
    # 2 | 00 | 03 for blue | green | red. (result // base^k) % base cuts the k-th digit.
    counts = {party: (result // base**k) % base for k, party in enumerate(parties)}
    assert counts == {"red": 3, "green": 0, "blue": 2}

    logger.info(f"✅ Encrypted election of parties test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name,key_size,kwargs", LARGE_PLAINTEXT_ALGORITHMS)
def test_trustees_tally_election_of_parties(algorithm_name, key_size, kwargs):
    """
    Trustees from competing parties hold shares of the key of a party election. A cheating
        trustee shifts its partial decryption to add 50 votes to its own party. Without
        proofs, the forged tally is accepted silently. With proofs, it is discarded.
    """
    from lightphe.commons.threshold import scaled_lagrange_coefficient

    authority_cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, **kwargs)
    share_keys = authority_cs.generate_threshold_keys(threshold=2, parties=3)
    trustees = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]

    parties = ["red", "green", "blue"]
    base = 100
    values = [base**k for k in range(len(parties))]

    votes = {"alice": "red", "bob": "blue", "carol": "red", "dave": "green", "erin": "red"}
    ballots = {
        voter: authority_cs.encrypt_with_proof(values[parties.index(party)], values=values, context=voter)
        for voter, party in votes.items()
    }
    valid = [
        ballot
        for voter, (ballot, proof) in ballots.items()
        if authority_cs.verify_ciphertext(ballot, proof, values=values, context=voter)
    ]
    tally = valid[0]
    for ballot in valid[1:]:
        tally = tally + ballot

    def count(result: int) -> dict:
        return {party: (result // base**k) % base for k, party in enumerate(parties)}

    partials = [trustee.partial_decrypt(tally, prove=True) for trustee in trustees]
    assert count(authority_cs.combine_partial_decryptions(tally, partials[:2], verify=True)) == {
        "red": 3,
        "green": 1,
        "blue": 1,
    }

    # trustee 1 of blue party knows that trustee 2 joins the decryption, so it finds the
    # shift adding 50 votes to blue from public lagrange coefficients
    n = authority_cs.cs.keys["public_key"]["n"]
    modulo = authority_cs.cs.ciphertext_modulo
    delta = 6  # factorial of the number of trustees
    coefficient = scaled_lagrange_coefficient(index=1, indices=[1, 2], delta=delta)
    target = 50 * values[parties.index("blue")]
    shift = (target * 4 * delta * delta * pow(2 * coefficient, -1, n)) % n
    forged = {**partials[0], "value": (partials[0]["value"] * pow(1 + n, shift, modulo)) % modulo}

    # without proofs, blue gets 50 more votes silently
    forged_result = authority_cs.combine_partial_decryptions(tally, [forged, partials[1]])
    assert count(forged_result) == {"red": 3, "green": 1, "blue": 51}

    # with proofs, the forged partial decryption is discarded and the honest trustees decrypt
    result = authority_cs.combine_partial_decryptions(tally, [forged] + partials[1:], verify=True)
    assert count(result) == {"red": 3, "green": 1, "blue": 1}

    logger.info(f"✅ Trustees tally election of parties test succeeded for {algorithm_name}")


@pytest.mark.parametrize("algorithm_name,key_size,kwargs", ALL_ALGORITHMS)
def test_one_hot_election(algorithm_name, key_size, kwargs):
    """
    Voters cast one-hot ballots, i.e. one 0/1 ciphertext per party with a proof that
        exactly one of them is 1. Slots are summed homomorphically, so each party's votes
        are counted separately, and the number of parties is not limited. Counts stay
        small, so exponential ElGamal can decrypt them. Trustees decrypt with proofs.
    """
    authority_cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, **kwargs)
    share_keys = authority_cs.generate_threshold_keys(threshold=2, parties=3)
    trustees = [LightPHE(algorithm_name=algorithm_name, keys=keys) for keys in share_keys]

    parties = ["red", "green", "blue", "yellow", "purple", "orange", "black", "white"]
    votes = {
        "alice": "red",
        "bob": "blue",
        "carol": "red",
        "dave": "white",
        "erin": "blue",
        "frank": "red",
    }
    ballots = {
        voter: authority_cs.encrypt_one_hot(parties.index(party), options=len(parties), context=voter)
        for voter, party in votes.items()
    }

    # mallory copies alice's ballot, and oscar reorders bob's slots to vote for another party
    ballots["mallory"] = ballots["alice"]
    bob_ballot, bob_proof = ballots["bob"]
    ballots["oscar"] = (bob_ballot[1:] + bob_ballot[:1], bob_proof)

    valid = [
        ballot
        for voter, (ballot, proof) in ballots.items()
        if authority_cs.verify_one_hot(ballot, proof, context=voter)
    ]
    assert len(valid) == len(votes)

    # sum each slot over all ballots
    tally = valid[0]
    for ballot in valid[1:]:
        tally = [total + slot for total, slot in zip(tally, ballot)]

    counts = {}
    for party, encrypted_count in zip(parties, tally):
        partials = [trustee.partial_decrypt(encrypted_count, prove=True) for trustee in trustees[:2]]
        counts[party] = authority_cs.combine_partial_decryptions(encrypted_count, partials, verify=True)

    assert counts == {
        "red": 3, "green": 0, "blue": 2, "yellow": 0, "purple": 0, "orange": 0, "black": 0, "white": 1
    }

    logger.info(f"✅ One-hot election test succeeded for {algorithm_name}")


@pytest.mark.parametrize(
    "algorithm_name,key_size,prime_order",
    [
        ("Exponential-ElGamal", 128, True),
        ("EllipticCurve-ElGamal", None, False),
        ("Paillier", 128, False),
        ("Damgard-Jurik", 128, False),
    ],
)
def test_cheating_one_hot_ballots_are_rejected(algorithm_name, key_size, prime_order):
    """
    A cheating voter builds its ballot slot by slot, proving whatever it can
    """
    from lightphe.commons.zkp import one_hot_context

    cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, prime_order=prime_order)
    options = 3

    def cheat(slots: list, claimed_sum: int) -> tuple:
        ciphertexts, random_keys, slot_proofs = [], [], []
        for slot, plaintext in enumerate(slots):
            random_key = cs.cs.generate_random_key()
            ciphertext = cs.cs.encrypt(plaintext=plaintext, random_key=random_key)
            # a slot of 2 cannot be proven to be 0 or 1, so prove it as 1
            slot_proofs.append(
                cs.cs.prove_membership(
                    ciphertext=ciphertext,
                    plaintext=min(plaintext, 1),
                    random_key=random_key,
                    values=[0, 1],
                    context=one_hot_context(None, options, slot),
                )
            )
            ciphertexts.append(ciphertext)
            random_keys.append(random_key)
        total = ciphertexts[0]
        for ciphertext in ciphertexts[1:]:
            total = cs.cs.add(total, ciphertext)
        # claim that the sum is 1 although it is not
        sum_proof = cs.cs.prove_membership(
            ciphertext=total,
            plaintext=claimed_sum,
            random_key=cs.cs.combine_random_keys(random_keys),
            values=[claimed_sum],
            context=one_hot_context(None, options, "sum"),
        )
        return [cs.create_ciphertext_obj(c) for c in ciphertexts], {
            "slots": slot_proofs,
            "sum": sum_proof,
        }

    # an honest ballot built in the same way is valid
    ballot, proof = cheat([0, 1, 0], claimed_sum=1)
    assert cs.verify_one_hot(ballot, proof) is True

    # voting for two parties, voting twice for a party, or abstaining is rejected
    for slots in [[1, 1, 0], [2, 0, 0], [0, 0, 0]]:
        ballot, proof = cheat(slots, claimed_sum=1)
        assert cs.verify_one_hot(ballot, proof) is False, slots


def test_one_hot_invalid_inputs():
    cs = LightPHE(algorithm_name="Paillier", key_size=128)
    with pytest.raises(ValueError, match="Choice must be in"):
        cs.encrypt_one_hot(3, options=3)
    with pytest.raises(ValueError, match="at least 1"):
        cs.encrypt_one_hot(0, options=0)
    with pytest.raises(ValueError, match="must be integers"):
        cs.encrypt_one_hot(1.0, options=3)

    ballot, proof = cs.encrypt_one_hot(0, options=1)
    assert cs.verify_one_hot(ballot, proof) is True
    assert cs.verify_one_hot([], proof) is False
    assert cs.verify_one_hot(ballot, {}) is False
    assert cs.verify_one_hot(ballot, None) is False

    with pytest.raises(ValueError, match="does not support proving"):
        LightPHE(algorithm_name="RSA", key_size=50).encrypt_one_hot(0, options=2)
