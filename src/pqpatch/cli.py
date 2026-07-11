"""Typer CLI entry point. Thin by design -- all logic lives in library modules
so it is testable without going through argument parsing."""

from __future__ import annotations

import typer

from pqpatch import __version__
from pqpatch.settings import get_settings

app = typer.Typer(add_completion=False, help="nesy-pqpatch: verified PQC code migration.")


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


@app.command()
def env() -> None:
    """Print resolved settings (offline mode, cache/runs directories)."""
    s = get_settings()
    typer.echo(f"offline    = {s.offline}")
    typer.echo(f"cache_dir  = {s.cache_dir}")
    typer.echo(f"runs_dir   = {s.runs_dir}")
    typer.echo(f"repo_root  = {s.repo_root}")


if __name__ == "__main__":
    app()
