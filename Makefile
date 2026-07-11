.PHONY: install lint typecheck test test-unit test-rules test-integration \
        smoke rules-test corpus-stats reproduce-all artifact clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	ruff check src tests

typecheck:
	mypy

test: test-unit test-rules

test-unit:
	pytest tests/unit -v

test-rules:
	pytest tests/rules -v

test-integration:
	pytest tests/integration -v -m integration

# Phase-0 exit criterion (codebase-plan.md §5): detector(stub) -> proposer(replay)
# -> verifier(L1) -> trace, end to end, offline.
smoke:
	PQPATCH_OFFLINE=1 pytest tests/integration/test_smoke.py -v

rules-test:
	pytest tests/rules -v

corpus-stats:
	$(PYTHON) -m pqpatch.eval.corpus_stats

# Not yet meaningful until Phase 7 (full runs exist under runs/); wired now so
# the target exists and fails loudly rather than being invented later.
reproduce-all:
	PQPATCH_OFFLINE=1 $(PYTHON) -m pqpatch.eval.tables --all

artifact:
	@echo "Packaging deferred to Phase 8 (codebase-plan.md §5)." && exit 1

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
