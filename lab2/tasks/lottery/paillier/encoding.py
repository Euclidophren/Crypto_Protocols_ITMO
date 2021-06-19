import fractions
import math
import sys


class EncodedNumber(object):
    BASE = 16
    LOG2_BASE = math.log(BASE, 2)
    FLOAT_MANTISSA_BITS = sys.float_info.mant_dig

    def __init__(self, public_key, encoding, exponent):
        self.public_key = public_key
        self.encoding = encoding
        self.exponent = exponent

    @classmethod
    def encode(cls, public_key, scalar, precision=None, max_exponent=None):
        if precision is None:
            if isinstance(scalar, int):
                prec_exponent = 0
            elif isinstance(scalar, float):
                bin_flt_exponent = math.frexp(scalar)[1]
                bin_lsb_exponent = bin_flt_exponent - cls.FLOAT_MANTISSA_BITS
                prec_exponent = math.floor(bin_lsb_exponent / cls.LOG2_BASE)
            else:
                raise TypeError("Don't know the precision of type %s."
                                % type(scalar))
        else:
            prec_exponent = math.floor(math.log(precision, cls.BASE))
        if max_exponent is None:
            exponent = prec_exponent
        else:
            exponent = min(max_exponent, prec_exponent)

        int_rep = round(fractions.Fraction(scalar)
                        * fractions.Fraction(cls.BASE) ** -exponent)

        if abs(int_rep) > public_key.max_int:
            raise ValueError('Integer needs to be within +/- %d but got %d'
                             % (public_key.max_int, int_rep))

        return cls(public_key, int_rep % public_key.n, exponent)

    def decode(self):
        if self.encoding >= self.public_key.n:
            raise ValueError('Attempted to decode corrupted number')
        elif self.encoding <= self.public_key.max_int:
            mantissa = self.encoding
        elif self.encoding >= self.public_key.n - self.public_key.max_int:
            mantissa = self.encoding - self.public_key.n
        else:
            raise OverflowError('Overflow detected in decrypted number')

        if self.exponent >= 0:
            return mantissa * self.BASE ** self.exponent
        else:
            try:
                return mantissa / self.BASE ** -self.exponent
            except OverflowError as e:
                raise OverflowError(
                    'decoded result too large for a float') from e

    def decrease_exponent_to(self, new_exp):
        if new_exp > self.exponent:
            raise ValueError('New exponent %i should be more negative than'
                             'old exponent %i' % (new_exp, self.exponent))
        factor = pow(self.BASE, self.exponent - new_exp)
        new_enc = self.encoding * factor % self.public_key.n
        return self.__class__(self.public_key, new_enc, new_exp)
