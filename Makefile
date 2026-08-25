.PHONY: install lint typecheck test test-unit test-rules test-integration \
        smoke rules-test corpus-stats reproduce-all icc-report artifact \
        artifact-verify clean

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
	pytest tests/integration -v

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

# ICC paper quantities, figure inputs, and TeX macros from the six adjudicated
# seed-0 trap grids. The generator hard-fails on missing runs or labels.
icc-report:
	PQPATCH_OFFLINE=1 $(PYTHON) -m pqpatch.eval.icc_report \
		--out-dir ../Manuscript-ICC/generated

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

# Back up the two gitignored directories that hold irreplaceable evidence:
# runs/ (manifests + traces) and the model-response cache (the determinism
# boundary). Destination: $PQPATCH_ARCHIVE_DIR, default ~/pqpatch-evidence-archive.
# RUN THIS AFTER EVERY PAID EXPERIMENT GRID.
archive:
	./tools/archive-evidence.sh archive

archive-list:
	./tools/archive-evidence.sh list

# Prove the determinism boundary holds: every committed run must regenerate
# from the cache with the network disabled.
verify-offline:
	PQPATCH_OFFLINE=1 $(PYTHON) -m pqpatch.eval.verify_evidence

artifact:
	PQPATCH_OFFLINE=1 $(PYTHON) -m pqpatch.eval.artifact \
		--out dist/pqpatch-icc-evidence.zip

artifact-verify:
	$(PYTHON) -m pqpatch.eval.artifact \
		--verify dist/pqpatch-icc-evidence.zip

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
