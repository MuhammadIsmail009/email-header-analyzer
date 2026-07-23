"""Shared rate limiter instance.

Kept in its own module so both ``main.py`` (which registers it on the app) and the
route modules (which decorate individual endpoints with it) can import it without a
circular dependency.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
