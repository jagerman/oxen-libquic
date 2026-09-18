"""QUIC for Python, built on libquic."""

from ._core import Address, Credentials, __version__
from .errors import (
    ConnectionFailed,
    QuicError,
    RequestError,
    RequestTimeout,
    StreamClosed,
)

__all__ = [
    "Address",
    "ConnectionFailed",
    "Credentials",
    "QuicError",
    "RequestError",
    "RequestTimeout",
    "StreamClosed",
    "__version__",
]
