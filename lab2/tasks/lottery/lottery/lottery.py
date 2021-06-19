from random import randint
from functools import reduce
from lab2.tasks.lottery.paillier.paillier import generate_paillier_keypair
from lab2.tasks.lottery.paillier.encoding import EncodedNumber


class Lottery:
    def __init__(self,
                 n: int):
        self.n = n
        self.keys = generate_paillier_keypair()
        self.tickets = self.generate_tickets()

    def generate_tickets(self):
        tickets = {
            num: EncodedNumber.encode(
                self.keys[0], randint(1, pow(2, 35))
            ).encoding for num in range(self.n)
        }
        return tickets

    def get_winner(self):
        numbers = self.tickets.values()
        product = reduce(lambda x, y: x * y, numbers)
        s = EncodedNumber(self.keys[0], product, exponent=0).decode()
        return s % self.n

    def __str__(self):
        for k, v in self.tickets.items():
            print(f'{k}: {v}')
