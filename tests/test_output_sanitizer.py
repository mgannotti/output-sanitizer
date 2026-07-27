"""Tests for output-sanitizer."""

from __future__ import annotations

import json

import pytest

import output_sanitizer as osan
from scoutkit.io import EvidenceError


def analyze(body: str, tmp_path, *, recipients=None, allow=(), require_recipients=False):
    path = tmp_path / "draft.json"
    payload = {"body": body}
    if recipients is not None:
        payload["to"] = recipients
    path.write_text(json.dumps(payload), encoding="utf-8")
    return osan.analyze(osan.argparse.Namespace(
        input=str(path), outdir=str(tmp_path / "out"), basename="output-sanitizer",
        allow_contact=list(allow), require_recipients=require_recipients, no_redacted_copy=False,
    ))


def codes(report) -> set[str]:
    return {f.code for f in report.findings}


class TestLeakageRules:
    @pytest.mark.parametrize(
        ("body", "code"),
        [
            ("The key is sk-ABCDEFGHIJKLMNOPQRSTUV and it works.", "OS001"),
            ("api_key=supersecretvalue123", "OS001"),
            ("Microsoft Confidential - Internal Only", "OS004"),
            ("Do not distribute outside the company.", "OS004"),
            ("My flight lands Tuesday evening.", "OS002"),
            ("I have a doctor's appointment Wednesday.", "OS002"),
            ("I'm on vacation next week.", "OS002"),
            ("Build server is at https://build-01.internal/pipeline", "OS005"),
            ("As we discussed in our internal leadership sync, we agreed.", "OS006"),
            ("The file is at C:\\Users\\example\\Documents\\plan.xlsx", "OS008"),
            ("Regards, ${sender_name}", "OS009"),
            ("Status: TODO before sending", "OS009"),
        ],
    )
    def test_rule_fires(self, body, code, tmp_path):
        assert code in codes(analyze(body, tmp_path))

    def test_clean_draft_passes(self, tmp_path):
        report = analyze(
            "Hi there,\n\nThanks for the call. We are targeting the end of the quarter for the "
            "first milestone. Let me know if Thursday works.\n\nBest,\nAlex\n", tmp_path)
        assert report.verdict == "pass"
        assert report.findings == []

    def test_credentials_block_the_draft(self, tmp_path):
        assert analyze("token: sk-AAAAAAAAAAAAAAAAAAAAAA", tmp_path).verdict == "block"

    def test_classification_marker_blocks_the_draft(self, tmp_path):
        assert analyze("Highly Confidential material follows.", tmp_path).verdict == "block"


class TestRecipientAwareness:
    def test_stray_address_is_flagged(self, tmp_path):
        report = analyze("Please loop in dana@other.test on this.", tmp_path,
                         recipients=["partner@external.test"])
        assert "OS003" in codes(report)

    def test_recipient_address_in_body_is_not_flagged(self, tmp_path):
        report = analyze("Sending this to partner@external.test as agreed.", tmp_path,
                         recipients=["partner@external.test"])
        assert "OS003" not in codes(report)

    def test_allowlisted_address_is_not_flagged(self, tmp_path):
        report = analyze("Contact support@vendor.test for help.", tmp_path,
                         recipients=["partner@external.test"], allow=["support@vendor.test"])
        assert "OS003" not in codes(report)

    def test_phone_number_is_flagged(self, tmp_path):
        assert "OS003" in codes(analyze("Reach me at (555) 010-4477 anytime.", tmp_path))

    def test_require_recipients_flags_a_bare_draft(self, tmp_path):
        report = analyze("Ordinary body text with nothing sensitive.", tmp_path, require_recipients=True)
        assert "OS011" in codes(report)


class TestQuotedHistory:
    def test_large_quoted_block_is_flagged(self, tmp_path):
        quoted = "\n".join("> prior message line " + str(i) for i in range(8))
        assert "OS010" in codes(analyze(f"See below.\n\n{quoted}\n", tmp_path))

    def test_short_quote_is_not_flagged(self, tmp_path):
        assert "OS010" not in codes(analyze("As you said:\n> one line\n\nAgreed.", tmp_path))


class TestRedaction:
    def test_redacted_copy_removes_the_secret(self, tmp_path):
        analyze("The key is sk-ABCDEFGHIJKLMNOPQRSTUV here.", tmp_path)
        redacted = (tmp_path / "out" / "output-sanitizer.redacted.txt").read_text(encoding="utf-8")
        assert "sk-ABCDEFGHIJKLMNOPQRSTUV" not in redacted
        assert "[REDACTED-CREDENTIAL]" in redacted

    def test_redaction_preserves_surrounding_prose(self, tmp_path):
        analyze("Before text. My flight lands Tuesday. After text.", tmp_path)
        redacted = (tmp_path / "out" / "output-sanitizer.redacted.txt").read_text(encoding="utf-8")
        assert "Before text." in redacted and "After text." in redacted

    def test_no_redacted_copy_flag_suppresses_the_file(self, tmp_path):
        path = tmp_path / "d.json"
        path.write_text(json.dumps({"body": "sk-ABCDEFGHIJKLMNOPQRSTUV"}), encoding="utf-8")
        osan.analyze(osan.argparse.Namespace(
            input=str(path), outdir=str(tmp_path / "out"), basename="b",
            allow_contact=[], require_recipients=False, no_redacted_copy=True))
        assert not (tmp_path / "out" / "b.redacted.txt").exists()

    def test_overlapping_spans_do_not_corrupt_output(self, tmp_path):
        analyze("Path C:\\Users\\me\\x and key api_key=abcdefgh together.", tmp_path)
        redacted = (tmp_path / "out" / "output-sanitizer.redacted.txt").read_text(encoding="utf-8")
        assert "[REDACTED" in redacted
        assert "together." in redacted


class TestLoading:
    def test_accepts_plain_text(self, write, tmp_path):
        path = write("draft.md", "Just a plain draft body with enough words.")
        report = osan.analyze(osan.argparse.Namespace(
            input=str(path), outdir=str(tmp_path / "o"), basename="b",
            allow_contact=[], require_recipients=False, no_redacted_copy=True))
        assert report.summary["recipients_declared"] == 0

    def test_json_without_body_is_an_evidence_error(self, write):
        path = write("d.json", json.dumps({"subject": "no body"}))
        with pytest.raises(EvidenceError):
            osan.load_draft(str(path))

    def test_empty_text_draft_is_an_evidence_error(self, write):
        with pytest.raises(EvidenceError):
            osan.load_draft(str(write("d.txt", "   \n  ")))

    def test_recipients_are_gathered_from_all_fields(self, write):
        path = write("d.json", json.dumps({"body": "x", "to": ["a@x.test"],
                                           "cc": ["b@x.test"], "bcc": "c@x.test"}))
        assert osan.load_draft(str(path)).recipients == ("a@x.test", "b@x.test", "c@x.test")


class TestBundledExample:
    def test_example_draft_blocks_on_multiple_rules(self, template, tmp_path):
        report = osan.analyze(osan.argparse.Namespace(
            input=str(template("output-sanitizer", "draft.example.json")),
            outdir=str(tmp_path / "o"), basename="b",
            allow_contact=[], require_recipients=False, no_redacted_copy=False))
        assert report.verdict == "block"
        assert {"OS001", "OS002", "OS003", "OS004", "OS005", "OS006", "OS008", "OS009"} <= codes(report)
        assert report.summary["redactions_applied"] > 0


class TestCli:
    def test_fail_on_block_returns_two(self, template, tmp_path):
        code = osan.main(["--input", str(template("output-sanitizer", "draft.example.json")),
                          "--outdir", str(tmp_path / "o"), "--fail-on", "block", "--quiet"])
        assert code == 2

    def test_missing_draft_returns_three(self, tmp_path):
        assert osan.main(["--input", str(tmp_path / "none.json"),
                          "--outdir", str(tmp_path / "o"), "--quiet"]) == 3
