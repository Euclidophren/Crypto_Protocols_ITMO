from random import (
    randint,
    choice
)

from time import sleep


class Alibaba:
    def __init__(self):
        self.has_secret = randint(0, 1)
        self.path = self.walk()

    def walk(self):
        return choice(['left', 'right'])


class Thieve:
    @staticmethod
    def choose_path():
        return choice(['left', 'right'])


if __name__ == '__main__':
    while True:
        ali, thieve = Alibaba(), Thieve().choose_path()
        print(f'Knows secret: {ali.has_secret}, Got it: {ali.path == thieve}')
        sleep(1)
