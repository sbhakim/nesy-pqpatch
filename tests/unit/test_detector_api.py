"""Pure API-level tests for classifying a shared Semgrep scan."""

from __future__ import annotations

from pathlib import Path

from pqpatch.detector.api import _site_id, recover_recorded_site
from pqpatch.model import UsageClass


def test_recover_recorded_site_restores_legacy_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "Verifier.java"
    source.write_text(
        'Signature verifier = Signature.getInstance("SHA256withRSA");\n'
        "verifier.initVerify(key);\n",
        encoding="utf-8",
    )
    site_id = _site_id("trap-a", str(source.resolve()), 1, "pq-detect-signature")
    recovered = recover_recorded_site(
        tmp_path,
        repo_name="trap-a",
        site_id=site_id,
        usage_class=UsageClass.VERIFY,
    )
    assert recovered.usage_class is UsageClass.VERIFY
    assert recovered.repo == "trap-a"
    assert recovered.line == 1
    assert recovered.detector_rule_id == "pq-detect-signature"
