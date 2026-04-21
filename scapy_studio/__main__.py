"""
Module entry point for `python -m scapy_studio`.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from .main import main


if __name__ == "__main__":
    raise SystemExit(main())
