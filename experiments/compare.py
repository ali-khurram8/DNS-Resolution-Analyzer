"""Quick Do53 / DoT / DoH comparison for the live demo (client container).

    python3 experiments/compare.py [--n 5]
"""

from __future__ import annotations

import argparse
import statistics

from common import TRANSPORT_NAME
from transports import TRANSPORTS, Do53


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=5)
    n = p.parse_args().n
    Do53().first_query(TRANSPORT_NAME)               # warm Unbound's cache
    print(f"{'transport':10} {'first query (new conn)':>24} {'repeat query (reused)':>24}")
    for cls in TRANSPORTS:
        t = cls()
        first = [t.first_query(TRANSPORT_NAME) for _ in range(n)]
        t.open()
        t.query_open(TRANSPORT_NAME)
        rep = [t.query_open(TRANSPORT_NAME) for _ in range(n)]
        t.close()
        print(f"{t.name:10} {statistics.mean(first):18.1f} ms   {statistics.mean(rep):18.1f} ms")


if __name__ == "__main__":
    main()
