#!/usr/bin/env python
"""Summarise the hub's probe log as state TRANSITIONS, so a long run reads as a short story.
    docker compose logs hub --no-log-prefix | python scripts/log_transitions.py
"""
import re
import sys

PATTERN = re.compile(r"probe (\S+) state=(\w+) tunnel=(\w+) tcp=(\w+) rtsp=(\w+) age=(\S+) err=(.*)")


def main():
    prev, n = None, 0
    for line in sys.stdin:
        m = PATTERN.search(line)
        if not m:
            continue
        n += 1
        key = (m.group(2), m.group(3), m.group(4), m.group(5))
        if key != prev:
            print(f"probe #{n:<4} state={m.group(2):<12} tunnel={m.group(3):<5} tcp={m.group(4):<5} rtsp={m.group(5):<5} "
                  f"handshake_age={m.group(6):<6} {m.group(7)[:80]}")
            prev = key
    print(f"({n} probes in total)")


if __name__ == "__main__":
    main()
