import struct

from lab2.tasks.digital_signature.ciphers.Cipher import BaseCipher
from random import (
    choice,
    randint,
    randrange
)


class Elgamal(BaseCipher):
    def __init__(self,
                 p: int):
        self.p = p
        self.g = self.generate_primitive_root()
        self.x = randint(1, self.p)
        self.y = pow(self.g, self.x, self.p)
        self.session_key = self.get_session_key()

    # TODO Sage version
    def generate_primitive_root(self):
        coprime_set = {num for num in range(1, self.p) if self.xgcd(num, self.p)[0] == 1}
        ll = [g for g in range(1, self.p) if coprime_set == {pow(g, powers, self.p)
                                                             for powers in range(1, self.p)}]
        return choice(ll)

    def get_session_key(self):
        while True:
            k = randrange(1, self.p)
            modulus, x, _ = self.xgcd(k, self.p - 1)
            if modulus == 1:
                return k

    def public_key(self) -> tuple:
        public_key = (self.y, self.g, self.p)
        return public_key

    def private_key(self) -> tuple:
        return self.x

    def encrypt(self, filename_read, filename_write):
        with open(filename_read, "rb") as fr, open(filename_write, "w") as fw:
            data = fr.read()
            for item in data:
                a = pow(self.g, self.session_key, self.p)
                b = pow(self.y, self.session_key) * item % self.p
                fw.write(str(a) + ',' + str(b) + "\n")

    # TODO check
    def decrypt(self, filename_read, filename_write):
        with open(filename_read, "r") as fr, open(filename_write, "wb") as fw:
            line = fr.readline()
            while line:
                a, b = [int(arg) for arg in line.split(',')]
                byte = b * self.mul_inv(pow(a, self.x), pow(a, self.x)) % self.p
                fw.write(struct.pack('B', byte))
                line = fr.readline()

