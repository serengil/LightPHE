# 3rd party dependencies
from lightphe import LightPHE

# project dependencies
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_keys.py")


def test_key_restoration():
    algorithms = [
        "RSA",
        "ElGamal",
        "Exponential-ElGamal",
        "Paillier",
        "Damgard-Jurik",
        "Okamoto-Uchiyama",
        "Benaloh",
        "Naccache-Stern",
        "Goldwasser-Micali",
        "EllipticCurve-ElGamal",
    ]

    for algorithm_name in algorithms:
        private_key_file = f"/tmp/{algorithm_name}_secret.json"
        public_key_file = f"/tmp/{algorithm_name}_public.json"

        # unfortunately Naccache-Stern key generation isn't guaranteed to be completed
        if algorithm_name in ["Naccache-Stern", "Benaloh"]:
            onprem_cs = LightPHE(algorithm_name=algorithm_name, key_size=37)
        else:
            onprem_cs = LightPHE(algorithm_name=algorithm_name)
        onprem_cs.export_keys(private_key_file)
        onprem_cs.export_keys(public_key_file, public=True)
        del onprem_cs

        cloud_cs = LightPHE(algorithm_name=algorithm_name, key_file=public_key_file)

        m1 = 217
        m2 = 23
        k = 3

        c1 = cloud_cs.encrypt(m1)
        c2 = cloud_cs.encrypt(m2)

        if algorithm_name in ["RSA", "ElGamal"]:
            c3 = c1 * c2
        elif algorithm_name in ["Goldwasser-Micali"]:
            c3 = c1 ^ c2
        else:
            c3 = c1 + c2
            c4 = k * c1

        # restore on prem cryptosystem
        onprem_cs = LightPHE(algorithm_name=algorithm_name, key_file=private_key_file)

        if algorithm_name in ["RSA", "ElGamal"]:
            assert onprem_cs.decrypt(c3) == m1 * m2
        elif algorithm_name in ["Goldwasser-Micali"]:
            assert onprem_cs.decrypt(c3) == m1 ^ m2
        else:
            assert onprem_cs.decrypt(c3) == m1 + m2
            assert onprem_cs.decrypt(c4) == k * m1

        logger.info(f"✅ Key restoration test succeeded for {algorithm_name}")
