"""Tests for the LLM-as-judge labelling path.

The contract these pin down is not "the judge is right" -- no test can assert
that -- but that the protocol cannot be violated silently: a proposer may not
judge, the prompt may not leak the answer, and an unreadable verdict is an
error rather than a guess.
"""

from __future__ import annotations

import pytest

from pqpatch.eval.llm_judge import (
    DEFAULT_JUDGE_MODELS,
    PROPOSER_MODELS,
    JudgeProtocolError,
    Judgment,
    assert_judges_disjoint,
    judge_candidate,
    majority_label,
    parse_judgment,
    render_judge_prompt,
    unanimous,
)
from pqpatch.model import Policy, UsageClass

POLICY = Policy(
    name="test",
    version="v1",
    floors={UsageClass.SIGN: "ML-DSA-65", UsageClass.KEM: "ML-KEM-768"},
    hybrid_required={UsageClass.KEM: True, UsageClass.SIGN: False},
    allowed_randomness_sources=("SecureRandom",),
)


def test_default_judges_are_not_proposers() -> None:
    """The shipped judge set must be disjoint from the proposer set; if the
    backends are ever reshuffled this test is what catches the overlap."""
    assert not set(DEFAULT_JUDGE_MODELS) & PROPOSER_MODELS
    assert_judges_disjoint(DEFAULT_JUDGE_MODELS)


def test_proposer_may_not_judge() -> None:
    proposer = next(iter(PROPOSER_MODELS))
    with pytest.raises(JudgeProtocolError, match="must not also be proposers"):
        assert_judges_disjoint([proposer, "gpt-5.1"])


def test_single_judge_is_refused() -> None:
    with pytest.raises(JudgeProtocolError, match=">= 2 distinct judges"):
        assert_judges_disjoint(["gpt-5.1"])


def test_prompt_carries_policy_but_not_the_answer() -> None:
    """Blinding: the judge sees code and policy, never the trap's own metadata."""
    prompt = render_judge_prompt(
        fixture_source="class A { }",
        candidate_diff="- old\n+ new",
        usage_class=UsageClass.KEM,
        policy=POLICY,
    )
    assert "ML-KEM-768" in prompt
    assert "Hybrid (classical + post-quantum) required: yes" in prompt
    assert "class A { }" in prompt
    for leaked in ("trap", "U1", "U6", "PQ-HYB", "provenance", "CVE-", "rationale"):
        assert leaked not in prompt


def test_parse_reads_verdict_and_reason() -> None:
    j = parse_judgment("gpt-5.1", 'sure: {"unsafe": true, "reason": "keeps RSA path"}')
    assert j.unsafe is True
    assert j.reason == "keeps RSA path"
    assert j.model == "gpt-5.1"


@pytest.mark.parametrize(
    "raw", ["no json here", '{"unsafe": "yes"}', "{'unsafe': true}", '{"reason": "x"}']
)
def test_unreadable_verdict_is_an_error_never_a_guess(raw: str) -> None:
    """A mis-parsed label would enter the suite as fabricated ground truth, so
    every unreadable reply must raise rather than default either way."""
    with pytest.raises(JudgeProtocolError):
        parse_judgment("gpt-5.1", raw)


def test_judge_candidate_runs_every_judge() -> None:
    seen: list[str] = []

    def fake(model: str, prompt: str) -> str:
        seen.append(model)
        assert "Proposed patch" in prompt
        return '{"unsafe": false, "reason": "clean"}'

    out = judge_candidate(
        fixture_source="class A {}",
        candidate_diff="-a\n+b",
        usage_class=UsageClass.SIGN,
        policy=POLICY,
        judges=("gpt-5.1", "claude-haiku-4-5"),
        call=fake,
    )
    assert seen == ["gpt-5.1", "claude-haiku-4-5"]
    assert [j.unsafe for j in out] == [False, False]


def _j(model: str, unsafe: bool) -> Judgment:
    return Judgment(model=model, unsafe=unsafe, reason="", raw="")


def test_majority_and_ties_resolve_unsafe() -> None:
    assert majority_label([_j("a", True), _j("b", True), _j("c", False)]) is True
    assert majority_label([_j("a", False), _j("b", False)]) is False
    # A tie has no majority calling the patch clean; treating a contested patch
    # as safe is the error that matters, so ties go to unsafe.
    assert majority_label([_j("a", True), _j("b", False)]) is True


def test_unanimity_is_reported_separately() -> None:
    assert unanimous([_j("a", True), _j("b", True)]) is True
    assert unanimous([_j("a", True), _j("b", False)]) is False


def test_empty_aggregation_is_an_error() -> None:
    with pytest.raises(ValueError):
        majority_label([])
    with pytest.raises(ValueError):
        unanimous([])
