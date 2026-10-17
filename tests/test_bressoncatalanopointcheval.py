import copy
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_bressoncatalanopointcheval.py")

cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_size=50)


def test_api():
    tic = time.time()
    modulo = cs.cs.plaintext_modulo

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    # negative plaintexts and addition wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
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
        f"✅ Bresson-Catalano-Pointcheval api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_keys_are_well_formed():
    n = cs.cs.keys["public_key"]["n"]
    p = cs.cs.keys["private_key"]["p"]
    q = cs.cs.keys["private_key"]["q"]
    assert n == p * q
    assert p != q

    # p and q are safe primes
    for prime in [p, q]:
        assert pow(2, prime - 1, prime) == 1
        p_prime = (prime - 1) // 2
        assert pow(2, p_prime - 1, p_prime) == 1


def test_master_trapdoor():
    # factorization of n decrypts without the local trapdoor a
    for m in [0, 1, 17, 12345, cs.cs.plaintext_modulo - 1]:
        c = cs.encrypt(plaintext=m)
        assert cs.decrypt_with_master_key(c) == m
        assert cs.decrypt_with_master_key(c * 3 + c) == cs.decrypt(c * 4)


def test_master_key_decrypts_all_users():
    # authority generates the master key, and publishes n and g with its public key
    authority_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_size=50)
    authority_public_cs = LightPHE(
        algorithm_name="Bresson-Catalano-Pointcheval",
        keys={"public_key": authority_cs.cs.keys["public_key"]},
    )

    # each user generates its own key pair with the public key of the authority
    alice_keys = authority_public_cs.generate_user_keys()
    bob_keys = authority_public_cs.generate_user_keys()
    assert set(alice_keys["private_key"].keys()) == {"a"}
    assert alice_keys["public_key"]["n"] == authority_cs.cs.keys["public_key"]["n"]
    assert alice_keys["public_key"]["g"] == authority_cs.cs.keys["public_key"]["g"]
    assert alice_keys["public_key"]["h"] != bob_keys["public_key"]["h"]

    alice_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", keys=alice_keys)
    bob_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", keys=bob_keys)

    alice_c = alice_cs.encrypt(plaintext=123) + alice_cs.encrypt(plaintext=456)
    bob_c = bob_cs.encrypt(plaintext=1000) * 3

    # users decrypt their own ciphertexts
    assert alice_cs.decrypt(alice_c) == 579
    assert bob_cs.decrypt(bob_c) == 3000

    # but not each other's
    assert alice_cs.decrypt(bob_c) != 3000
    assert bob_cs.decrypt(alice_c) != 579

    # users do not have the master key
    with pytest.raises(ValueError, match="master trapdoor"):
        alice_cs.decrypt_with_master_key(bob_c)

    # authority decrypts ciphertexts of all users without knowing their local trapdoors
    assert authority_cs.decrypt_with_master_key(alice_c) == 579
    assert authority_cs.decrypt_with_master_key(bob_c) == 3000

    # authority may keep the master trapdoor only
    master_keys = copy.deepcopy(authority_cs.cs.keys)
    del master_keys["private_key"]["a"]
    master_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", keys=master_keys)
    assert master_cs.decrypt_with_master_key(alice_c) == 579
    assert master_cs.decrypt_with_master_key(bob_c) == 3000
    with pytest.raises(ValueError, match="local trapdoor"):
        master_cs.decrypt(alice_c)

    # encryption with public key of a user restored from a file is still decryptable
    restored_cs = LightPHE(
        algorithm_name="Bresson-Catalano-Pointcheval",
        keys={"public_key": bob_keys["public_key"]},
    )
    assert master_cs.decrypt_with_master_key(restored_cs.encrypt(plaintext=7)) == 7

    logger.info("✅ Bresson-Catalano-Pointcheval master key test succeeded")


def test_master_key_decrypts_tensors():
    user_cs = LightPHE(
        algorithm_name="Bresson-Catalano-Pointcheval", keys=cs.generate_user_keys()
    )
    enc_tensor = user_cs.encrypt([1.5, -2.25, 3], silent=True)
    assert cs.decrypt_with_master_key(enc_tensor) == [1.5, -2.25, 3]
    assert cs.decrypt_with_master_key(enc_tensor * 2) == [3, -4.5, 6]
    assert cs.decrypt(enc_tensor) != [1.5, -2.25, 3]


def test_master_key_of_another_system():
    other_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_size=50)
    c = other_cs.encrypt(plaintext=5)
    with pytest.raises(ValueError, match="does not share the same n and g"):
        cs.decrypt_with_master_key(c)


def test_master_key_requires_private_key(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)
    public_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=5)

    with pytest.raises(ValueError, match="You must have private key"):
        public_cs.decrypt_with_master_key(c)

    # public key is enough to generate user keys
    user_keys = public_cs.generate_user_keys()
    user_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", keys=user_keys)
    assert cs.decrypt_with_master_key(user_cs.encrypt(plaintext=9)) == 9


@pytest.mark.parametrize("algorithm_name", ["Paillier", "RSA", "Damgard-Geisler-Kroigaard"])
def test_master_key_unsupported_algorithms(algorithm_name):
    other_cs = LightPHE(algorithm_name=algorithm_name, key_size=50)
    c = other_cs.encrypt(plaintext=5)

    with pytest.raises(ValueError, match="does not support master key decryption"):
        other_cs.decrypt_with_master_key(c)

    with pytest.raises(ValueError, match="does not support generating user keys"):
        other_cs.generate_user_keys()


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Bresson-Catalano-Pointcheval predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    public_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * 2
    assert cs.decrypt(c) == 84

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_size=1024)
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == m1 * 1000
    assert large_cs.decrypt_with_master_key(c1 + c2) == m1 + m2

    # floats and tensors
    c3 = large_cs.encrypt(plaintext=1.5)
    assert large_cs.decrypt(c3 * 4) == 6
    enc_tensor = large_cs.encrypt([1.5, 2.25, 3.5], silent=True)
    assert large_cs.decrypt(enc_tensor) == [1.5, 2.25, 3.5]
    assert large_cs.decrypt(enc_tensor @ [2, 4, 1]) == [15.5]

    logger.info(
        f"✅ Bresson-Catalano-Pointcheval 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_readme_master_key(tmp_path):
    public_key_file = str(tmp_path / "public.txt")

    # authority generates the master key and publishes its public key
    authority_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_size=256)
    authority_cs.export_keys(target_file=public_key_file, public=True)

    # each user generates its own key pair with the public key of the authority
    public_cs = LightPHE(algorithm_name="Bresson-Catalano-Pointcheval", key_file=public_key_file)
    alice_cs = LightPHE(
        algorithm_name="Bresson-Catalano-Pointcheval", keys=public_cs.generate_user_keys()
    )
    bob_cs = LightPHE(
        algorithm_name="Bresson-Catalano-Pointcheval", keys=public_cs.generate_user_keys()
    )

    alice_ciphertext = alice_cs.encrypt(100) + alice_cs.encrypt(50)
    bob_ciphertext = bob_cs.encrypt(200)

    # users decrypt their own ciphertexts only
    assert alice_cs.decrypt(alice_ciphertext) == 150
    assert alice_cs.decrypt(bob_ciphertext) != 200

    # authority decrypts ciphertexts of all users
    assert authority_cs.decrypt_with_master_key(alice_ciphertext) == 150
    assert authority_cs.decrypt_with_master_key(bob_ciphertext) == 200
