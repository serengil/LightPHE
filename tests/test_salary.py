from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_salary.py")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Paillier", key_size=50)

    # set initial base salary to 10000 usd
    salary = 10000
    salary_encrypted = cs.encrypt(salary)

    # add 1000 usd to base salary
    wage_increase = 1000
    increase_encrypted = cs.encrypt(wage_increase)

    # perform homomorphic addition
    assert cs.decrypt(salary_encrypted + increase_encrypted) == salary + wage_increase

    # increase base salary 5%
    ratio = 1.05
    assert cs.decrypt(salary_encrypted * ratio) == salary * ratio
