from random import randrange
from lab2.tasks.digital_signature.ciphers.Cipher import BaseCipher
import struct


class RSA(BaseCipher):
    def __init__(self,
                 p: int,
                 q: int
                 ):
        self.p = p
        self.q = q
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = self.calculate_e()
        self.d = self.calculate_d()

    def calculate_e(self):
        while True:
            e = randrange(2, self.phi)
            modulus, x, _ = self.xgcd(e, self.phi)
            if modulus == 1:
                return e

    def calculate_d(self):
        return self.mul_inv(self.e, self.phi)

    def encrypt(self, filename_read, filename_write):
        with open(filename_read, "rb") as fr, open(filename_write, "w") as fw:
            data = fr.read()
            for item in data:
                new_item = pow(item, self.e, self.n)
                fw.write(str(new_item) + "\n")

    def decrypt(self, filename_read, filename_write):
        with open(filename_read, "r") as fr, open(filename_write, "wb") as fw:
            line = fr.readline()
            while line:
                num = int(line)
                byte = pow(num, self.d, self.n)
                fw.write(struct.pack('B', byte))
                line = fr.readline()

    def public_key(self):
        public_key = (self.e, self.n)
        return public_key

    def private_key(self):
        private_key = (self.d, self.n)
        return private_key


# if __name__ == '__main__':
#     filename = sys.argv[1]
#
#     if len(sys.argv) == 2:
#         p = 199
#         q = 179
#     else:
#         p = int(sys.argv[2])
#         q = int(sys.argv[3])
#     with open(filename, 'rb') as file1:
#         data = file1.read()
#         rsa = RSA(p, q)
#         print(rsa.__dict__)
#         print("Encrypting...")
#         rsa.encrypt(filename, filename.split(".")[0] + ".encoded")
#         print("Decrypting...")
#         rsa.decrypt(filename.split('.')[0] + ".encoded", filename.split('.')[0] + ".decoded")
