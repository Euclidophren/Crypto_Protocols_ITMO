from lab2.tasks.digital_signature.signature.Signature import BaseSignature
from random import randint
from lab2.tasks.digital_signature.ciphers.Cipher import BaseCipher


class ElGamalSignature(BaseSignature):
    def sign(self, filename_read, filename_write):
        while True:
            k = randint(1, self.public_key[2] - 1)
            modulo, x, _ = BaseCipher.xgcd(k, self.public_key[2] - 1)
            if modulo == 1:
                break
        with open(filename_read, "rb") as fr, open(filename_write, "w") as fw:
            data = fr.read()
            for item in data:
                new_item = pow(item, self.private_key, self.public_key[1])
                fw.write(str(new_item) + "\n")

    def get_prototype(self, filename_read, filename_write):
        with open(filename_read, "rb") as fr, open(filename_write, "w") as fw:
            data = fr.read()
            for item in data:
                new_item = pow(item, self.public_key[0], self.public_key[1])
                fw.write(str(new_item) + "\n")

    def verify(self, message, message_signed):
        ret = True
        with open(message, "rb") as fr, open(message_signed, "rb") as fw:
            data = fr.read()
            data_signed = fw.read()
            for item_messg, item_signed in zip(data, data_signed):
                if item_messg != item_signed:
                    ret = False
                    break
        return ret
