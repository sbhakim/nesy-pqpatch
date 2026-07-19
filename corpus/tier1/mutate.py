#!/usr/bin/env python
"""Thin entry point kept at the documented path; the implementation lives in
pqpatch.eval.mutate so it sits inside the linted, typed, tested package.

Usage: python corpus/tier1/mutate.py   (regenerates corpus/tier1/mutated/)
"""

import sys

from pqpatch.eval.mutate import main

if __name__ == "__main__":
    sys.exit(main())
