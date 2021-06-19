from abc import (
    ABC,
    abstractmethod
)
from typing import Optional


class BaseCipher(ABC):
    @property
    @abstractmethod
    def public_key(self) -> tuple:
        pass

    @property
    @abstractmethod
    def private_key(self) -> Optional[tuple]:
        pass

    @abstractmethod
    def encrypt(self, filename_read, filename_write) -> None:
        pass

    @abstractmethod
    def decrypt(self, filename_read, filename_write) -> None:
        pass

    @staticmethod
    def xgcd(a, b) -> list:
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            q, b, a = b // a, a, b % a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return [b, x0, y0]

    def mul_inv(self, a, b):
        g, x, _ = self.xgcd(a, b)
        if g == 1:
            return x % b
