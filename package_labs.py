"""package_labs.py — package -> live-lab registry for provtrail_bridge.

"Auto by ecosystem": ProvTrail flags JS/npm advisories, but the live exploit
probe (cve_pipeline stage 3) can only run when there is a real target for that
package. This registry maps an npm package name to the lab URL to point the
probe at. Anything NOT in the map runs static + patch analysis only
(``no_probe=True``) — we never claim a dynamic confirmation without a real
target.

Start empty and honest. Add an entry only once a real, runnable lab exists for
that package, e.g.::

    PACKAGE_LABS = {
        "fastify": "http://127.0.0.1:8000",
    }

Keys are the bare npm package name as ProvTrail reports it (``pkg=fastify``,
``pkg=fastify:unknown`` — the ``:status`` suffix is stripped before lookup).
"""

from __future__ import annotations

# npm package name -> lab URL for the live probe. Empty by default.
PACKAGE_LABS: dict[str, str] = {}


def _normalise(package: str) -> str:
    """Strip ProvTrail's ``:status`` suffix and whitespace: ``fastify:unknown`` -> ``fastify``."""
    return package.split(":", 1)[0].strip()


def lab_for_package(package: str | None) -> str | None:
    """Return the lab URL for *package*, or None when no matching lab exists."""
    if not package:
        return None
    return PACKAGE_LABS.get(_normalise(package))


def lab_for_packages(packages) -> str | None:
    """Return the first matching lab URL across *packages*, or None."""
    for package in packages or ():
        url = lab_for_package(package)
        if url:
            return url
    return None
