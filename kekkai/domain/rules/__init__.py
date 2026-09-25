"""Importing this package triggers registration of every deterministic rule."""

from . import (  # noqa: F401
    egress_allowlist,
    mass_delete,
    path_escape,
    secret_read,
    shell_exec,
)
