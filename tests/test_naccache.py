import time
import pytest
from lightphe.cryptosystems.NaccacheStern import NaccacheStern
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_naccache.py")


def test_naccache_on_plaintexts():
    cs = NaccacheStern(key_size=37, deterministic=False)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    assert cs.decrypt(c1) == m1 % cs.plaintext_modulo
    assert cs.decrypt(c2) == m2 % cs.plaintext_modulo

    # homomorphic operations
    assert cs.decrypt(cs.add(c1, c2)) == (m1 + m2) % cs.plaintext_modulo
    assert (
        cs.decrypt(cs.multiply_by_constant(c2, m1)) == (m1 * m2) % cs.plaintext_modulo
    )

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    # re-encryption
    c1_prime = cs.reencrypt(c1)
    assert c1_prime != c1
    assert cs.decrypt(c1_prime) == m1 % cs.plaintext_modulo
    logger.info("✅ Probabilistic Naccache-Stern test succeeded")


def test_deterministic_version():
    cs = NaccacheStern(deterministic=True, key_size=37)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    assert cs.decrypt(c1) == m1 % cs.plaintext_modulo
    assert cs.decrypt(c2) == m2 % cs.plaintext_modulo

    # homomorphic operations
    assert cs.decrypt(cs.add(c1, c2)) == (m1 + m2) % cs.plaintext_modulo
    assert (
        cs.decrypt(cs.multiply_by_constant(c2, m1)) == (m1 * m2) % cs.plaintext_modulo
    )

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    with pytest.raises(ValueError):
        cs.reencrypt(c1)

    logger.info("✅ Deterministic Naccache-Stern test succeeded")


def test_predefined_keys():
    """
    Key generation of Naccache-Stern is probabilistic and may take time.
        and may not succeed sometimes. Test encrypt, decrypt and homomorphic
        operations performances with predefined keys.
    """
    keys = {
        "public_key": {
            "n": 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653839478670263258301833023097636036737220721033604997817044724812266620826468829212603338614968953684914579782761554925497589591101127424868060977977362624693729,
            "g": 2322858651861384064537514431822509724460178869240342120700966005387085547272373554253264326744794826709642720143603083090045603237528622393527254537059946505389885957837759097286992580665451178640443489482838164247603492906332153298019557819758033383394570549848334276102748452532710144646257390863266986629778942,
            "sigma": 255255,
        },
        "private_key": {
            "a": 11597041531885171702428009785553891872754255798746286340205448513302430749967682685453809973100036260110796582178813477436613205882229456042479325870287379,
            "b": 6357265649357031680615244845679689252112451833267362870520093680285536565908774220658104716644696735431871010152670595233003071273441498122136618828384989,
            "p": 2435378721695886057509882054966317293278393717736720131443144187793510457493213363945300094351007614623267282257550830261688773235268185768920658432760349591,
            "q": 30909025587173888031151320439694649143770740813345918276468695473548278783448460260839705132326515527669756851362284434022860932531472563869828240743607816519,
            "phi": 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653806134265954388527744361895141375770783671899073915178636812972605279037227887538978553609742276161772286758627935090233305041395360684118422229078186256527620,
            "prime_set": [3, 5, 7, 11, 13, 17],
        },
    }

    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Naccache-Stern", keys=keys)

    security_level = cs.cs.keys["public_key"]["n"].bit_length()

    logger.info(
        f"Naccache-Stern cs built with {security_level} bits key. Recommended >= 768."
    )

    m1 = 17
    m2 = 21

    tic = time.time()
    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)
    toc = time.time()
    logger.info(f"Naccache-Stern encryption time: {(toc - tic)/2:.4f} seconds")

    # homomorphic addition
    tic = time.time()
    assert cs.decrypt(c1 + c2) == m1 + m2
    toc = time.time()
    logger.info(f"Naccache-Stern homomorphic addition time: {(toc - tic):.4f} seconds")

    # homomorphic scalar multiplication
    tic = time.time()
    c1_times_m2 = c1 * m2
    c2_times_m1 = c2 * m1
    m2_times_c1 = m2 * c1
    m1_times_c2 = m1 * c2
    toc = time.time()
    logger.info(
        f"Naccache-Stern homomorphic scalar multiplication time: {(toc - tic)/4:.4f} seconds"
    )

    assert cs.decrypt(c1_times_m2) == m1 * m2
    assert cs.decrypt(c2_times_m1) == m1 * m2
    assert cs.decrypt(m2_times_c1) == m1 * m2
    assert cs.decrypt(m1_times_c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Naccache-Stern api test with pre-defined keys succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Naccache-Stern", key_size=37)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Naccache-Stern api test succeeded")


@pytest.mark.skip(reason="We cannot generate Naccache-Stern keys always")
def test_api_with_real_keys():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Naccache-Stern")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Naccache-Stern api test succeeded")
