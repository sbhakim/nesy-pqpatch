"""Prompt assembly from context, policy, and repair feedback.

Kept out of the backend adapters so every backend receives byte-identical
prompts for the same inputs. Templates are versioned and never edited in
place.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from pqpatch.model import Context, Policy

_PROMPTS_ROOT = Path(__file__).parent.parent / "extractor" / "prompts"

_env_cache: dict[str, Environment] = {}


def _env(version: str) -> Environment:
    if version not in _env_cache:
        # autoescape stays off (S701): these are plain-text prompts carrying
        # Java source; HTML-escaping would corrupt content like List<String>.
        _env_cache[version] = Environment(  # noqa: S701
            loader=FileSystemLoader(str(_PROMPTS_ROOT / version)),
            undefined=StrictUndefined,  # missing template variables are hard errors
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _env_cache[version]


def render_prompt(
    context: Context,
    policy: Policy,
    *,
    feedback: str | None,
    attempt: int,
    prompt_version: str = "v1",
) -> str:
    template = _env(prompt_version).get_template("migrate.jinja2")
    return template.render(
        site=context.site,
        context=context,
        policy=policy,
        feedback=feedback,
        attempt=attempt,
    )
