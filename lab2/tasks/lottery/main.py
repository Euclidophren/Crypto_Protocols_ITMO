from argparse import ArgumentParser
from lab2.tasks.lottery.lottery.lottery import Lottery


def get_parser():
    parser = ArgumentParser()
    parser.add_argument('--n', action='store', type=int, help='number of people')
    return parser


if __name__ == '__main__':
    parser = get_parser()
    arguments = parser.parse_args()
    n = arguments.n
    lottery = Lottery(n)
    winner = lottery.get_winner()
    print(winner)
