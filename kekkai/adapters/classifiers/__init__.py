"""Importing this package registers every backend.

Laya and Jev import unconditionally even though their third-party packages are extras: both
defer that import until first use. So a backend is always *known* and, when its extra is
missing, says "the `laya` extra is not installed" at the point of use rather than presenting as
an unknown backend name. That is a better error, and it keeps the core dependency-free.
"""

from .deterministic import DeterministicClassifier  # noqa: F401
from .jev import JevClassifier  # noqa: F401
from .laya import LayaClassifier  # noqa: F401
from .registry import all_backends, get_backend, register_backend  # noqa: F401
from .replay import ReplayClassifier, StaticClassifier  # noqa: F401
