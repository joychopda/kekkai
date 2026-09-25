"""Backend registry.

Deliberately shaped like `importlib.metadata` entry points so a production build could swap to
them without touching a call site -- the same convention the sibling repos use for their rule
and mutator plugins.
"""

from __future__ import annotations

from ...application.ports import ClassifierPort

_BACKENDS: dict[str, type[ClassifierPort]] = {}


def register_backend(cls: type[ClassifierPort]) -> type[ClassifierPort]:
    name = getattr(cls, "name", None)
    if not name or name == "unnamed":
        raise ValueError(f"{cls.__name__} must define a class-level `name`")
    _BACKENDS[name] = cls
    return cls


def all_backends() -> dict[str, type[ClassifierPort]]:
    return dict(_BACKENDS)


def get_backend(name: str) -> type[ClassifierPort]:
    try:
        return _BACKENDS[name]
    except KeyError as exc:
        raise KeyError(f"unknown backend {name!r}; available: {sorted(_BACKENDS)}") from exc
