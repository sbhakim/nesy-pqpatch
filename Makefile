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

# RQ0: detector precision/recall vs. Tier-2 ground truth. Offline, no model.
table-detection:
	$(PYTHON) -m pqpatch.eval.detection

# Funnel + trap summaries from run manifests (loud-fails without runs), and
# the .tex row fragments a results pass would \input.
tables:
	PQPATCH_OFFLINE=1 $(PYTHON) -m pqpatch.eval.tables --latex-dir runs/_latex

# Regenerate the Tier-1 mutated surface (needs tier1/original intake first).
tier1-mutate:
	$(PYTHON) -m pqpatch.eval.mutate

# Everything regenerable offline today: corpus state, RQ0, manifest tables.
# corpus-stats exits nonzero by design while the corpus is incomplete; the
# leading '-' records that honestly without aborting the rest.
reproduce-all:
	-$(MAKE) corpus-stats
	$(MAKE) table-detection
	$(MAKE) tables

artifact:
	@echo "Packaging deferred to Phase 8 (codebase-plan.md §5)." && exit 1

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
