from lab2.tasks.digital_signature.ciphers.RSA import RSA
from lab2.tasks.digital_signature.ciphers.ElGamal import Elgamal
from lab2.tasks.digital_signature.signature.RSA import RSASignature
from time import time


def time_tests(filename_read, filename_encrypted, filename_signed):
    rsa_cipher = RSA(17, 19)
    elgamal_cipher = Elgamal(19)
    rsa_signature = RSASignature(rsa_cipher.private_key(), rsa_cipher.public_key())

    print('Processing...')
    start = time()
    rsa_cipher.encrypt(filename_read, filename_encrypted)
    rsa_signature.sign(filename_read, filename_signed)
    stop = time() - start
    print(f'Time to execute: {stop}')
    print('Another one...')
    start = time()
    elgamal_cipher.encrypt(filename_read, filename_encrypted)
    rsa_signature.sign(filename_read, filename_signed)
    stop = time() - start
    print(f'Time to execute: {stop}')


if __name__ == '__main__':
    filename_read = 'E:\\protocols\\lab2\\tasks\\digital_signature\\tests\\discrete_log.py'
    filename_encrypted = 'E:\\protocols\\lab2\\tasks\\digital_signature\\tests\\discrete_log.py.encrypted'
    filename_signed = 'E:\\protocols\\lab2\\tasks\\digital_signature\\tests\\discrete_log.py.signed'
    time_tests(filename_read, filename_encrypted, filename_signed)
