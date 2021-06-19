from abc import (
    ABC,
    abstractmethod
)


class BaseSignature(ABC):
    def __init__(self,
                 private_key,
                 public_key
                 ):
        self.private_key = private_key
        self.public_key = public_key

    @abstractmethod
    def sign(self, filename_read, filename_write):
        pass

    @abstractmethod
    def get_prototype(self, filename_read, filename_write):
        pass

    @abstractmethod
    def verify(self, message, message_signed):
        pass
