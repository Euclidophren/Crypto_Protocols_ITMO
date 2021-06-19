from math import ceil, sqrt
from typing import Optional


def bsgs(g, h, p) -> Optional[int]:
    n = ceil(sqrt(p - 1))
    tbl = {pow(g, i, p): i for i in range(n)}
    c = pow(g, n * (p - 2), p)
    for j in range(n):
        y = (h * pow(c, j, p)) % p
        if y in tbl:
            return j * n + tbl[y]
    return None
