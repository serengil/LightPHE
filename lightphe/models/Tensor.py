from typing import Union, List


# pylint: disable=too-few-public-methods
class EncryptedTensor:
    def __init__(
        self,
        dividend: Union[int, tuple, list],
        divisor: Union[int, tuple, list],
        sign: Union[int, tuple, list],
    ):
        self.dividend = dividend
        self.divisor = divisor
        self.sign = sign

    def __str__(self):
        return f"EncryptedTensor({self.sign} * {self.dividend} / {self.divisor})"

    def __repr__(self):
        return self.__str__()


class EncryptedTensors:
    def __init__(self, encrypted_tensor: List[EncryptedTensor]):
        self.encrypted_tensor = encrypted_tensor

    def __str__(self):
        results = []
        for i in self.encrypted_tensor:
            results.append(f"{i}")
        return ", ".join(results)

    def __repr__(self):
        return self.__str__()
