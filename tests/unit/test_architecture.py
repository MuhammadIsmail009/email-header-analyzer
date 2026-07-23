"""Structural guarantees about the codebase itself, not about any one module's logic.

These assert the boundary claims made in ``docs/ARCHITECTURE.md`` and
``PROJECT_PLAN.md`` §5 are actually true, rather than merely documented as true. A
claim like "app/core has no web-framework imports" is worth nothing if nothing ever
checks it after the day it was written.
"""

from __future__ import annotations

import ast
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[2] / "app" / "core"

_FORBIDDEN_MODULE_PREFIXES = ("fastapi", "starlette", "jinja2", "uvicorn")


def _imported_module_names(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _core_python_files() -> list[Path]:
    return sorted(CORE_DIR.rglob("*.py"))


def test_core_directory_is_not_empty():
    """Guards the test itself: if this returns [], every check below passes vacuously
    and silently stops meaning anything."""
    files = _core_python_files()
    assert len(files) >= 15, f"expected many core modules, found {len(files)}"


def test_core_has_no_web_imports():
    """app/core must not import FastAPI, Starlette, Jinja2 or Uvicorn.

    This is what allows app/core to be tested — and to have been fully built and
    tested during Phases 2, 4 and 6 — entirely independently of the web layer. A
    violation here means core has silently taken on a framework dependency it
    shouldn't need, which is exactly the kind of coupling that makes a module
    untestable without spinning up a server.
    """
    violations: list[str] = []
    for path in _core_python_files():
        source = path.read_text(encoding="utf-8")
        imported = _imported_module_names(source)
        for module in imported:
            if any(
                module == prefix or module.startswith(prefix + ".")
                for prefix in _FORBIDDEN_MODULE_PREFIXES
            ):
                violations.append(f"{path.relative_to(CORE_DIR.parent.parent)}: imports {module!r}")

    assert not violations, "app/core imported a web-framework module:\n" + "\n".join(violations)


def test_core_verification_is_the_only_subpackage_doing_dns_io():
    """A softer structural check: only verification/ should import dnspython/pyspf/
    dkimpy directly. Everything else in core should stay pure — receiving a Resolver
    or a pre-computed result rather than doing its own I/O."""
    io_libraries = ("dns", "spf", "dkim")
    offenders: list[str] = []

    for path in _core_python_files():
        if "verification" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        imported = _imported_module_names(source)
        for module in imported:
            top_level = module.split(".")[0]
            if top_level in io_libraries:
                offenders.append(f"{path.relative_to(CORE_DIR.parent.parent)}: imports {module!r}")

    assert not offenders, "DNS/crypto I/O library imported outside verification/:\n" + "\n".join(offenders)
