"""Live transport for the blind LLM judge panel (eval/llm_judge.py).

`llm_judge` is deliberately pure: it renders a blind prompt and parses a
verdict, taking the network call as an injected `JudgeFn` so the unit suite
runs offline. This module is that injection for real runs, and it exists
separately so nothing in the labelling logic depends on a vendor SDK.

**Refusals are a first-class outcome, not an error.** Measured 2026-08-23,
`claude-opus-5` declined roughly a third of adjudications with
`stop_reason: "refusal"` and `category: "cyber"` -- judging a
security-weakening patch trips the same classifier that makes some models
decline to propose one. That arrives as HTTP 200 with no content, so a naive
transport reads it as an empty response and either crashes or, far worse,
silently coerces it to a verdict. Both would be fabricated ground truth.

`JudgeRefusal` is therefore raised distinctly, the adjudicator records which
judge refused on which patch, and the verdict is decided by the judges that did
answer -- provided at least two remain. At a refusal rate this high, judge
availability is a real methodological constraint and belongs in the paper
rather than in a silently-dropped row.
"""

from __future__ import annotations

import httpx

from pqpatch.settings import Settings

_ANTHROPIC_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_TIMEOUT_S = 120.0

# Which vendor serves which judge. Kept explicit rather than inferred from the
# model string, so adding a judge is a deliberate edit and a typo cannot
# silently route a model to the wrong endpoint.
_ANTHROPIC_JUDGES = frozenset({"claude-haiku-4-5", "claude-opus-5", "claude-sonnet-5"})


class JudgeTransportError(RuntimeError):
    """The judge could not be reached, or answered in a shape we cannot use."""


class JudgeRefusal(RuntimeError):
    """The judge declined to answer (HTTP 200, safety stop).

    Distinct from a transport failure and from an unparsable verdict: the
    request succeeded and the model chose not to rule on this patch.
    """


def _call_anthropic(model: str, prompt: str, api_key: str) -> str:
    payload = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {"x-api-key": api_key, "anthropic-version": _ANTHROPIC_VERSION}
    with httpx.Client(base_url=_ANTHROPIC_BASE, timeout=_TIMEOUT_S) as client:
        resp = client.post("/v1/messages", json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    if data.get("stop_reason") == "refusal":
        details = data.get("stop_details") or {}
        raise JudgeRefusal(f"{model} declined (category={details.get('category')!r})")
    text = "".join(block.get("text", "") for block in data.get("content", []))
    if not text.strip():
        # No refusal marker but nothing to read: treat as a refusal rather than
        # inventing a verdict. Erring toward "no label" is always recoverable;
        # erring toward a fabricated label is not.
        raise JudgeRefusal(f"{model} returned an empty completion")
    return text


def _call_openai_compatible(model: str, prompt: str, api_key: str, base_url: str) -> str:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_completion_tokens": 1024,
    }
    headers = {"Authorization": f"Bearer {api_key}"}
    with httpx.Client(base_url=base_url, timeout=_TIMEOUT_S) as client:
        resp = client.post("/chat/completions", json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise JudgeTransportError(f"{model} returned no choices")
    choice = choices[0]
    if choice.get("finish_reason") == "content_filter":
        raise JudgeRefusal(f"{model} declined (content_filter)")
    text = (choice.get("message") or {}).get("content") or ""
    if not text.strip():
        raise JudgeRefusal(f"{model} returned an empty completion")
    return text


def make_judge_fn(settings: Settings, *, openai_base_url: str) -> object:
    """Build the `JudgeFn` llm_judge.judge_candidate expects.

    Routing is by explicit membership, and a model this module does not know
    how to reach is an error rather than a guess -- a judge silently sent to
    the wrong endpoint would produce labels attributed to the wrong model.
    """

    def call(model: str, prompt: str) -> str:
        if model in _ANTHROPIC_JUDGES:
            key = settings.backend_b_api_key
            if not key:
                raise JudgeTransportError(
                    f"judge {model!r} needs PQPATCH_BACKEND_B_API_KEY (Anthropic)"
                )
            return _call_anthropic(model, prompt, key)
        key = settings.backend_a_api_key
        if not key:
            raise JudgeTransportError(
                f"judge {model!r} needs PQPATCH_BACKEND_A_API_KEY (OpenAI-compatible)"
            )
        return _call_openai_compatible(model, prompt, key, openai_base_url)

    return call
