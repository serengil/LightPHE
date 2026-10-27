import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_auction.py")


@pytest.mark.parametrize(
    "algorithm_name,key_size,prime_order",
    [("Exponential-ElGamal", 128, True), ("Paillier", 128, False)],
)
def test_sealed_bid_auction(algorithm_name, key_size, prime_order):
    """
    Bidders submit encrypted bids with proofs of knowledge. A bidder who copies someone
        else's encrypted bid and adds 1 to it homomorphically cannot prove knowledge of
        the result, so cannot outbid without knowing the bid. After the deadline, the
        auctioneer decrypts valid bids with proofs and announces the winner.
    """
    auctioneer_cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, prime_order=prime_order)
    public_cs = LightPHE(
        algorithm_name=algorithm_name, keys={"public_key": auctioneer_cs.cs.keys["public_key"]}
    )

    bids = {"alice": 950, "bob": 870, "carol": 910}
    submissions = {
        bidder: public_cs.encrypt_with_proof_of_knowledge(bid, context=bidder)
        for bidder, bid in bids.items()
    }

    # mallory copies alice's encrypted bid, adds 1 to it, and reuses alice's proof
    alice_bid, alice_proof = submissions["alice"]
    submissions["mallory"] = (alice_bid + public_cs.encrypt(1), alice_proof)

    # oscar re-randomizes bob's encrypted bid to make it look different
    bob_bid, bob_proof = submissions["bob"]
    submissions["oscar"] = (public_cs.regenerate_ciphertext(bob_bid), bob_proof)

    # trent submits a copy of carol's submission as is
    submissions["trent"] = submissions["carol"]

    valid = {
        bidder: bid
        for bidder, (bid, proof) in submissions.items()
        if public_cs.verify_knowledge(bid, proof, context=bidder)
    }
    assert sorted(valid) == sorted(bids)

    # after the deadline, auctioneer decrypts valid bids with proofs, and anyone verifies them
    opened = {}
    for bidder, bid in valid.items():
        amount, proof = auctioneer_cs.decrypt_with_proof(bid)
        assert public_cs.verify_decryption(bid, amount, proof) is True
        opened[bidder] = amount

    assert opened == bids
    assert max(opened, key=opened.get) == "alice"

    logger.info(f"✅ Sealed-bid auction test succeeded for {algorithm_name}")
