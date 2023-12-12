from lightphe.cryptosystems.Paillier import Paillier
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_salary.py")


def test_salary():
    cs = Paillier()

    # set initial base salary to 10000 usd
    salary = 10000
    salary_encrypted = cs.encrypt(salary)

    # add 1000 usd to base salary
    wage_increase = 1000
    increase_encrypted = cs.encrypt(wage_increase)

    # calculate new salary on encrypted data
    new_salary_encrypted = cs.add(salary_encrypted, increase_encrypted)

    # new salary should be 11000 usd
    assert cs.decrypt(new_salary_encrypted) == 11000

    # increase new salary 5%. in other words, multiply salary with 1.05
    # 105 / 100 can be represented as 105 * 100^-1
    ratio = 105 * pow(100, -1, cs.plaintext_modulo)

    # final salary should be 11000 x 1.05 = 11500
    final_salary_encrytped = cs.multiply_by_contant(new_salary_encrypted, ratio)
    assert cs.decrypt(final_salary_encrytped) == 11550

    logger.info("✅ Salary test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Paillier")

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
