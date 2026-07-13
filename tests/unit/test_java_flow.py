"""Focused tests for the bounded PQ-VER-01 Java def-use slice."""

from pqpatch.verifier.l2_dataflow.java_flow import VerifyUse, classify_verify_uses


def _method(body: str) -> str:
    return f"""
        final class Subject {{
            boolean check(Signature signature, byte[] input) {{
                {body}
            }}
        }}
    """


def test_direct_return_is_explicitly_propagated() -> None:
    source = _method("return signature.verify(input);")
    assert classify_verify_uses(source) == [VerifyUse.CHECKED]


def test_simple_alias_reaching_branch_is_checked() -> None:
    source = _method("""
        boolean valid = signature.verify(input);
        boolean accepted = valid;
        if (!accepted) { return false; }
        return true;
    """)
    assert classify_verify_uses(source) == [VerifyUse.CHECKED]


def test_discarded_result_is_rejected() -> None:
    source = _method("signature.verify(input); return true;")
    assert classify_verify_uses(source) == [VerifyUse.DISCARDED]


def test_result_overwritten_before_branch_is_rejected() -> None:
    source = _method("""
        boolean valid = signature.verify(input);
        valid = true;
        if (valid) { return true; }
        return false;
    """)
    assert classify_verify_uses(source) == [VerifyUse.DISCARDED]


def test_alias_survives_overwrite_of_original_variable() -> None:
    source = _method("""
        boolean valid = signature.verify(input);
        boolean accepted = valid;
        valid = true;
        if (accepted) { return true; }
        return false;
    """)
    assert classify_verify_uses(source) == [VerifyUse.CHECKED]


def test_comment_does_not_create_verify_fact() -> None:
    source = _method("// signature.verify(input);\nreturn true;")
    assert classify_verify_uses(source) == []


def test_nested_verify_in_condition_is_checked() -> None:
    source = _method(
        "if (input.length > 0 && signature.verify(input)) { return true; } return false;"
    )
    assert classify_verify_uses(source) == [VerifyUse.CHECKED]


def test_string_does_not_create_verify_fact() -> None:
    source = _method('String text = "signature.verify(input)"; return true;')
    assert classify_verify_uses(source) == []


def test_malformed_java_is_indeterminate() -> None:
    source = _method("return signature.verify(input)")
    assert classify_verify_uses(source) == [VerifyUse.INDETERMINATE]


def test_shadowed_result_name_is_indeterminate() -> None:
    source = _method("""
        {
            boolean valid = signature.verify(input);
        }
        {
            boolean valid = true;
            if (valid) { return true; }
        }
        return false;
    """)
    assert classify_verify_uses(source) == [VerifyUse.INDETERMINATE]


def test_nested_class_facts_do_not_shadow_outer_method_result() -> None:
    source = _method("""
        boolean valid = signature.verify(input);
        Object helper = new Object() {
            boolean check() {
                boolean valid = true;
                return valid;
            }
        };
        return valid;
    """)
    assert classify_verify_uses(source) == [VerifyUse.CHECKED]
