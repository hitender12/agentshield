"""Thin entry point kept for ``python demo.py``.

The demo lives in :mod:`agentshield.demo` so the installed console
script can import it too (a top-level ``demo`` module is not importable
once the package is installed).
"""

from agentshield.demo import run_demo

if __name__ == "__main__":
    run_demo()
