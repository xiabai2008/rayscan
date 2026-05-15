"""
Allows running via python -m wvs
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
