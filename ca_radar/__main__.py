"""Entry point for ``python -m ca_radar``.

Enables the Docker distroless runtime to invoke the CLI without relying on
the venv wrapper script (whose shebang references the builder's Python path).
"""

from ca_radar.cli import app

app()
