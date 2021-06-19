import random
from lab2.tasks.lottery.paillier.encoding import EncodedNumber
from lab2.tasks.lottery.paillier.utils import invert, powmod, getprimeover, isqrt

DEFAULT_KEYSIZE = 3072


def generate_paillier_keypair(private_keyring=None, n_length=DEFAULT_KEYSIZE):
    p = q = n = None
    n_len = 0
    while n_len != n_length:
        p = getprimeover(n_length // 2)
        q = p
        while q == p:
            q = getprimeover(n_length // 2)
        n = p * q
        n_len = n.bit_length()

    public_key = PaillierPublicKey(n)
    private_key = PaillierPrivateKey(public_key, p, q)

    if private_keyring is not None:
        private_keyring.add(private_key)

    return public_key, private_key


class PaillierPublicKey(object):
    def __init__(self, n):
        self.g = n + 1
        self.n = n
        self.nsquare = n * n
        self.max_int = n // 3 - 1

    def __repr__(self):
        public_key_hash = hex(hash(self))[2:]
        return "<PaillierPublicKey {}>".format(public_key_hash[:10])

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def raw_encrypt(self, plaintext, r_value=None):
        if not isinstance(plaintext, int):
            raise TypeError('Expected int type plaintext but got: %s' %
                            type(plaintext))

        if self.n - self.max_int <= plaintext < self.n:
            # Very large plaintext, take a sneaky shortcut using inverses
            neg_plaintext = self.n - plaintext  # = abs(plaintext - nsquare)
            neg_ciphertext = (self.n * neg_plaintext + 1) % self.nsquare
            nude_ciphertext = invert(neg_ciphertext, self.nsquare)
        else:
            # we chose g = n + 1, so that we can exploit the fact that
            # (n+1)^plaintext = n*plaintext + 1 mod n^2
            nude_ciphertext = (self.n * plaintext + 1) % self.nsquare

        r = r_value or self.get_random_lt_n()
        obfuscator = powmod(r, self.n, self.nsquare)

        return (nude_ciphertext * obfuscator) % self.nsquare

    def get_random_lt_n(self):
        return random.SystemRandom().randrange(1, self.n)

    def encrypt(self, value, precision=None, r_value=None):
        if isinstance(value, EncodedNumber):
            encoding = value
        else:
            encoding = EncodedNumber.encode(self, value, precision)

        return self.encrypt_encoded(encoding, r_value)

    def encrypt_encoded(self, encoding, r_value):
        obfuscator = r_value or 1
        ciphertext = self.raw_encrypt(encoding.encoding, r_value=obfuscator)
        encrypted_number = EncryptedNumber(self, ciphertext, encoding.exponent)
        if r_value is None:
            encrypted_number.obfuscate()
        return encrypted_number


class PaillierPrivateKey(object):
    def __init__(self, public_key, p, q):
        if not p * q == public_key.n:
            raise ValueError('given public key does not match the given p and q.')
        if p == q:
            # check that p and q are different, otherwise we can't compute p^-1 mod q
            raise ValueError('p and q have to be different')
        self.public_key = public_key
        if q < p:  # ensure that p < q.
            self.p = q
            self.q = p
        else:
            self.p = p
            self.q = q
        self.psquare = self.p * self.p

        self.qsquare = self.q * self.q
        self.p_inverse = invert(self.p, self.q)
        self.hp = self.h_function(self.p, self.psquare)
        self.hq = self.h_function(self.q, self.qsquare)

    @staticmethod
    def from_totient(public_key, totient):
        p_plus_q = public_key.n - totient + 1
        p_minus_q = isqrt(p_plus_q * p_plus_q - public_key.n * 4)
        q = (p_plus_q - p_minus_q) // 2
        p = p_plus_q - q
        if not p * q == public_key.n:
            raise ValueError('given public key and totient do not match.')
        return PaillierPrivateKey(public_key, p, q)

    def __repr__(self):
        pub_repr = repr(self.public_key)
        return "<PaillierPrivateKey for {}>".format(pub_repr)

    def decrypt(self, encrypted_number):
        encoded = self.decrypt_encoded(encrypted_number)
        return encoded.decode()

    def decrypt_encoded(self, encrypted_number, Encoding=None):
        if not isinstance(encrypted_number, EncryptedNumber):
            raise TypeError('Expected encrypted_number to be an EncryptedNumber'
                            ' not: %s' % type(encrypted_number))

        if self.public_key != encrypted_number.public_key:
            raise ValueError('encrypted_number was encrypted against a '
                             'different key!')

        if Encoding is None:
            Encoding = EncodedNumber

        encoded = self.raw_decrypt(encrypted_number.ciphertext(be_secure=False))
        return Encoding(self.public_key, encoded,
                        encrypted_number.exponent)

    def raw_decrypt(self, ciphertext):
        if not isinstance(ciphertext, int):
            raise TypeError('Expected ciphertext to be an int, not: %s' %
                            type(ciphertext))

        decrypt_to_p = self.l_function(powmod(ciphertext, self.p - 1, self.psquare), self.p) * self.hp % self.p
        decrypt_to_q = self.l_function(powmod(ciphertext, self.q - 1, self.qsquare), self.q) * self.hq % self.q
        return self.crt(decrypt_to_p, decrypt_to_q)

    def h_function(self, x, xsquare):
        return invert(self.l_function(powmod(self.public_key.g, x - 1, xsquare), x), x)

    def l_function(self, x, p):
        return (x - 1) // p

    def crt(self, mp, mq):
        u = (mq - mp) * self.p_inverse % self.q
        return mp + (u * self.p)

    def __eq__(self, other):
        return self.p == other.p and self.q == other.q

    def __hash__(self):
        return hash((self.p, self.q))


class EncryptedNumber(object):
    def __init__(self, public_key, ciphertext, exponent=0):
        self.public_key = public_key
        self.__ciphertext = ciphertext
        self.exponent = exponent
        self.__is_obfuscated = False
        if isinstance(self.ciphertext, EncryptedNumber):
            raise TypeError('ciphertext should be an integer')
        if not isinstance(self.public_key, PaillierPublicKey):
            raise TypeError('public_key should be a PaillierPublicKey')

    def ciphertext(self, be_secure=True):
        if be_secure and not self.__is_obfuscated:
            self.obfuscate()

        return self.__ciphertext

    def decrease_exponent_to(self, new_exp):
        if new_exp > self.exponent:
            raise ValueError('New exponent %i should be more negative than '
                             'old exponent %i' % (new_exp, self.exponent))
        multiplied = self * pow(EncodedNumber.BASE, self.exponent - new_exp)
        multiplied.exponent = new_exp
        return multiplied

    def obfuscate(self):
        r = self.public_key.get_random_lt_n()
        r_pow_n = powmod(r, self.public_key.n, self.public_key.nsquare)
        self.__ciphertext = self.__ciphertext * r_pow_n % self.public_key.nsquare
        self.__is_obfuscated = True

    def _add_scalar(self, scalar):
        encoded = EncodedNumber.encode(self.public_key, scalar,
                                       max_exponent=self.exponent)

        return self._add_encoded(encoded)

    def _add_encoded(self, encoded):
        if self.public_key != encoded.public_key:
            raise ValueError("Attempted to add numbers encoded against "
                             "different public keys!")

        # In order to add two numbers, their exponents must match.
        a, b = self, encoded
        if a.exponent > b.exponent:
            a = self.decrease_exponent_to(b.exponent)
        elif a.exponent < b.exponent:
            b = b.decrease_exponent_to(a.exponent)

        encrypted_scalar = a.public_key.raw_encrypt(b.encoding, 1)

        sum_ciphertext = a._raw_add(a.ciphertext(False), encrypted_scalar)
        return EncryptedNumber(a.public_key, sum_ciphertext, a.exponent)

    def _add_encrypted(self, other):
        if self.public_key != other.public_key:
            raise ValueError("Attempted to add numbers encrypted against "
                             "different public keys!")

        # In order to add two numbers, their exponents must match.
        a, b = self, other
        if a.exponent > b.exponent:
            a = self.decrease_exponent_to(b.exponent)
        elif a.exponent < b.exponent:
            b = b.decrease_exponent_to(a.exponent)

        sum_ciphertext = a._raw_add(a.ciphertext(False), b.ciphertext(False))
        return EncryptedNumber(a.public_key, sum_ciphertext, a.exponent)

    def _raw_add(self, e_a, e_b):
        return e_a * e_b % self.public_key.nsquare

    def _raw_mul(self, plaintext):
        if not isinstance(plaintext, int):
            raise TypeError('Expected ciphertext to be int, not %s' %
                            type(plaintext))

        if plaintext < 0 or plaintext >= self.public_key.n:
            raise ValueError('Scalar out of bounds: %i' % plaintext)

        if self.public_key.n - self.public_key.max_int <= plaintext:
            # Very large plaintext, play a sneaky trick using inverses
            neg_c = invert(self.ciphertext(False), self.public_key.nsquare)
            neg_scalar = self.public_key.n - plaintext
            return powmod(neg_c, neg_scalar, self.public_key.nsquare)
        else:
            return powmod(self.ciphertext(False), plaintext, self.public_key.nsquare)
