"""The template-rewriter baseline: a deterministic, LLM-free proposer.

RQ4's ablation asks whether the neural component is decorative. This backend is
the non-neural arm: it rewrites the algorithm literal at the detected site line
to the policy floor for the site's usage class, and nothing else. It cannot
restructure code, construct a hybrid, follow indirection, or use feedback --
every attempt returns the same patch, so a rejected template escalates at k by
construction. Where the site's algorithm is not a literal on the detected line
(configuration lookups, concatenation), it emits an empty diff, which the
migration-obligation rule PQ-MIG-01 rejects as a no-op: the template's
inability to even engage such sites is real ablation data, not an error.

It overrides ``propose`` rather than ``_generate_raw`` because a template needs
the site and policy, not a rendered prompt; being fully deterministic, it also
needs no response cache -- reproducibility is by construction, not by replay.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from pathlib import Path

from pqpatch.model import Context, Patch, Policy
from pqpatch.proposer.base import Backend
from pqpatch.settings import Settings

_GETINSTANCE_LITERAL = re.compile(r'getInstance\(\s*"([^"]+)"')
_PQ_TOKEN = re.compile(r"ML-KEM|ML-DSA|SLH-DSA|MLKEM|MLDSA|SLHDSA")


class TemplateBackend(Backend):
    backend_id = "template-rewriter"
    model_version = "template-v1"

    def __init__(self, settings: Settings) -> None:
        # Deliberately does not call super().__init__: the base constructor
        # exists to wire the response cache, and a deterministic rewriter has
        # nothing to cache. Settings is accepted for interface symmetry.
        self._settings = settings

    def _generate_raw(
        self, prompt: str, *, seed: int, site_id: str, attempt: int
    ) -> tuple[str, int]:
        raise NotImplementedError("TemplateBackend overrides propose(); no raw generation")

    def propose(
        self,
        context: Context,
        policy: Policy,
        *,
        feedback: str | None,
        attempt: int,
        seed: int = 0,
        prompt_version: str = "v1",
    ) -> Patch:
        del feedback, seed  # templates cannot repair and have no sampling
        site = context.site
        target = policy.floors.get(site.usage_class)

        original = Path(site.file_path).read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        diff = ""
        claimed = ""

        if target is not None and 0 < site.line <= len(lines):
            line = lines[site.line - 1]
            match = _GETINSTANCE_LITERAL.search(line)
            if match and not _PQ_TOKEN.search(match.group(1)):
                new_line = (
                    line[: match.start(1)] + target + line[match.end(1) :]
                )
                patched = lines.copy()
                patched[site.line - 1] = new_line
                diff = "".join(
                    difflib.unified_diff(
                        lines,
                        patched,
                        fromfile=f"a/{site.file_path}",
                        tofile=f"b/{site.file_path}",
                    )
                )
                claimed = target

        return Patch(
            site_id=site.site_id,
            attempt=attempt,
            unified_diff=diff,
            claimed_primitive=claimed,
            claimed_parameters=claimed,
            backend_id=self.backend_id,
            prompt_version=prompt_version,
            response_hash=hashlib.sha256(diff.encode("utf-8")).hexdigest(),
        )
