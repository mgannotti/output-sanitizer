#!/usr/bin/env python3
"""output-sanitizer — catch private-data leakage in a draft before it is sent.

Checks any outbound draft (email, Teams message, channel post, meeting body) for
content that should not leave the session: credentials, sensitivity markers,
schedule and travel disclosure, third-party contact details, internal hostnames,
and local filesystem paths. Emits a verdict and a redacted copy of the draft.

Offline. Never sends anything. Refuses to be the thing that transmits.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Iterable, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from scoutkit import Finding, Report, Severity, read_json, read_text, write_text  # noqa: E402
from scoutkit.cli import run  # noqa: E402
from scoutkit.io import EvidenceError  # noqa: E402

SKILL = "output-sanitizer"
TITLE = "Output Sanitizer — outbound leakage check"


class Rule(NamedTuple):
    code: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    detail: str
    recommendation: str
    redact_as: str


def _rx(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


RULES: tuple[Rule, ...] = (
    Rule(
        "OS001", Severity.CRITICAL, "Credential material",
        _rx(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
            r"|\b(?:password|passwd|api[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|connection[_\s-]?string)"
            r"\s*[:=]\s*\S{6,}"),
        "A secret, token, or password appears in the draft body.",
        "Remove it and rotate the credential. Never transmit secrets over mail or chat.",
        "[REDACTED-CREDENTIAL]",
    ),
    Rule(
        "OS004", Severity.CRITICAL, "Sensitivity label leakage",
        _rx(r"\b(?:highly\s+confidential|confidential\s*(?:\\|/|—|-)\s*\w+|internal\s+only|restricted\s+data"
            r"|company\s+confidential|not\s+for\s+(?:external\s+)?distribution|do\s+not\s+distribute)\b"),
        "The draft carries an internal classification marker, which means the content behind it is classified too.",
        "Confirm the recipient is cleared for this classification, or remove the classified passage entirely.",
        "[REDACTED-CLASSIFIED]",
    ),
    Rule(
        "OS002", Severity.HIGH, "Private schedule or travel disclosure",
        _rx(r"\b(?:my\s+flight|i'?m\s+flying|boarding\s+pass|i'?ll\s+be\s+in\s+[A-Z][a-z]+"
            r"|i'?m\s+(?:on\s+(?:vacation|pto|leave)|out\s+of\s+(?:the\s+)?(?:office|country))"
            r"|doctor'?s?\s+appointment|medical\s+appointment|surgery|therapy\s+session"
            r"|picking\s+up\s+(?:my\s+)?(?:kid|son|daughter|child)|school\s+pickup"
            r"|hotel\s+(?:reservation|confirmation)|my\s+home\s+address)\b"),
        "The draft discloses the sender's location, health, family, or travel plans.",
        "Replace with a neutral statement of availability. Never explain why you are unavailable.",
        "[REDACTED-PRIVATE]",
    ),
    Rule(
        "OS005", Severity.HIGH, "Internal host or private endpoint",
        _rx(r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|[\w.-]+\.(?:internal|corp|local|intranet|test))\b"
            r"|\bhttps?://[\w-]+-my\.sharepoint\.com/personal/\S+"),
        "An internal or personal endpoint is exposed. External recipients cannot reach it and should not know it exists.",
        "Replace with a properly shared link, or drop the reference.",
        "[REDACTED-INTERNAL-URL]",
    ),
    Rule(
        "OS006", Severity.MEDIUM, "Reference to a private conversation",
        _rx(r"\b(?:as\s+(?:we\s+)?discussed\s+in\s+(?:our|the)\s+(?:1:1|one[\s-]on[\s-]one|private|internal|leadership)"
            r"|per\s+the\s+internal\s+(?:thread|email|discussion|memo)"
            r"|from\s+(?:our|the)\s+(?:internal|private|leadership|exec(?:utive)?)\s+"
            r"(?:call|meeting|sync|thread|channel))\b"),
        "The draft cites a conversation the recipient was not part of, revealing that it happened and who was in it.",
        "Restate the conclusion on its own merits without naming the private forum.",
        "[REDACTED-SOURCE]",
    ),
    Rule(
        "OS008", Severity.MEDIUM, "Local filesystem path",
        _rx(r"[A-Za-z]:\\Users\\[^\s\"'<>|,;)\]]+|/(?:home|Users)/[\w.-]+/[\w./-]+"),
        "A local path exposes the sender's username and machine layout, and is unusable to the recipient.",
        "Attach the file or share a link instead of pasting a path.",
        "[REDACTED-PATH]",
    ),
    Rule(
        "OS009", Severity.MEDIUM, "Unresolved placeholder",
        re.compile(r"\$\{[^}]+\}|<[a-z][a-z0-9_-]{1,30}>|\{\{[^}]+\}\}|\b(?:TODO|TBD|FIXME|XXX|LOREM\s+IPSUM)\b"),
        "A template placeholder survived into the draft.",
        "Fill in the value before sending. Placeholders in outbound mail read as careless.",
        "[UNFILLED]",
    ),
)

_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
_QUOTE_BLOCK = re.compile(r"^(?:>\s?.*(?:\n|$)){6,}", re.MULTILINE)


class Draft(NamedTuple):
    body: str
    recipients: tuple[str, ...]
    subject: str


def load_draft(path: str) -> Draft:
    """Accept a plain text/markdown draft, or JSON with body/to/cc/subject."""
    p = Path(path)
    if not p.is_file():
        raise EvidenceError(f"no such file: {p}")

    if p.suffix.lower() == ".json":
        payload = read_json(p)
        if not isinstance(payload, dict):
            raise EvidenceError("draft JSON must be an object with a 'body' field")
        body = payload.get("body") or payload.get("content") or payload.get("text")
        if not isinstance(body, str) or not body.strip():
            raise EvidenceError("draft JSON must contain a non-empty 'body'")
        recipients = []
        for key in ("to", "cc", "bcc", "recipients"):
            value = payload.get(key)
            if isinstance(value, str):
                recipients.append(value)
            elif isinstance(value, list):
                recipients.extend(str(v) for v in value)
        return Draft(body, tuple(sorted({r.lower().strip() for r in recipients if r})), str(payload.get("subject") or ""))

    text = read_text(p)
    if not text.strip():
        raise EvidenceError(f"draft is empty: {p}")
    return Draft(text, (), "")


def _recipient_domains(recipients: Iterable[str]) -> set[str]:
    return {r.split("@", 1)[1] for r in recipients if "@" in r}


def analyze(args: argparse.Namespace) -> Report:
    draft = load_draft(args.input)
    report = Report(skill=SKILL, subject=Path(args.input).name)
    text = draft.body
    matched_spans: list[tuple[int, int, str]] = []

    def add(code: str, severity: str, title: str, detail: str, rec: str, evidence: str = "") -> None:
        report.add(Finding(code=code, severity=severity, title=title, detail=detail,
                           locator=Path(args.input).name, evidence=evidence, recommendation=rec))

    for rule in RULES:
        matches = list(rule.pattern.finditer(text))
        if not matches:
            continue
        for match in matches:
            matched_spans.append((match.start(), match.end(), rule.redact_as))
        sample = " ".join(matches[0].group(0).split())[:80]
        add(rule.code, rule.severity, rule.title,
            f"{rule.detail} {len(matches)} occurrence(s).", rule.recommendation, sample)

    # Third-party contact details that are not part of the recipient set.
    known = set(draft.recipients) | {a.lower() for a in (args.allow_contact or [])}
    stray_emails = sorted({m.group(0).lower() for m in _EMAIL.finditer(text)} - known)
    external = [e for e in stray_emails if e.split("@", 1)[1] not in _recipient_domains(draft.recipients)] \
        if draft.recipients else stray_emails
    if stray_emails:
        severity = Severity.HIGH if external else Severity.MEDIUM
        add("OS003", severity, "Third-party contact details in the body",
            f"{len(stray_emails)} address(es) appear in the body but are not on the recipient list: "
            f"{', '.join(stray_emails[:5])}.",
            "Remove them, or add the people to the recipient list so the disclosure is intentional.",
            stray_emails[0])
        for match in _EMAIL.finditer(text):
            if match.group(0).lower() in set(stray_emails):
                matched_spans.append((match.start(), match.end(), "[REDACTED-CONTACT]"))

    phones = list(_PHONE.finditer(text))
    if phones:
        add("OS003", Severity.HIGH, "Phone number in the body",
            f"{len(phones)} phone number(s) present.",
            "Confirm the number is the sender's own and that the recipient should have it.",
            phones[0].group(0))
        matched_spans.extend((m.start(), m.end(), "[REDACTED-PHONE]") for m in phones)

    quotes = _QUOTE_BLOCK.findall(text)
    if quotes:
        longest = max(len(q) for q in quotes)
        add("OS010", Severity.MEDIUM, "Large verbatim quoted block",
            f"{len(quotes)} quoted block(s), longest {longest} characters. "
            "Forwarded history often carries content the new recipient was never meant to see.",
            "Trim the quoted history to only what the recipient needs.")

    if args.require_recipients and not draft.recipients:
        add("OS011", Severity.MEDIUM, "No recipient list supplied",
            "Recipient-relative checks were skipped because the draft declares no recipients.",
            "Provide the draft as JSON with a 'to' field so third-party disclosure can be evaluated.")

    redacted = _redact(text, matched_spans)
    redacted_path = None
    if not args.no_redacted_copy:
        redacted_path = write_text(Path(args.outdir) / f"{args.basename}.redacted.txt", redacted)

    report.sections = {
        "recipients": list(draft.recipients),
        "subject": draft.subject,
        "redacted_copy": str(redacted_path) if redacted_path else None,
    }
    report.summary = {
        "body_characters": len(text),
        "recipients_declared": len(draft.recipients),
        "redactions_applied": len(matched_spans),
        "rules_triggered": len({f.code for f in report.findings}),
    }
    report.note("A pass verdict is not permission to send. You remain the approver.")
    if redacted_path:
        report.note(f"Redacted copy written to {redacted_path}.")
    report.decide_verdict(block_at=Severity.CRITICAL, review_at=Severity.MEDIUM)
    return report


def _redact(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping replacements from the end so offsets stay valid."""
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: (s[0], -s[1]))
    merged: list[tuple[int, int, str]] = []
    for start, end, token in ordered:
        if merged and start < merged[-1][1]:
            continue
        merged.append((start, end, token))
    out = text
    for start, end, token in reversed(merged):
        out = out[:start] + token + out[end:]
    return out


def _extend(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--allow-contact", nargs="*", default=[],
                        help="Addresses that may legitimately appear in the body.")
    parser.add_argument("--require-recipients", action="store_true",
                        help="Flag drafts that declare no recipient list.")
    parser.add_argument("--no-redacted-copy", action="store_true",
                        help="Report only; do not write the redacted draft.")


def main(argv: list[str] | None = None) -> int:
    return run(argv, skill=SKILL, title=TITLE, analyze=analyze, extend=_extend,
               description="Check an outbound draft for private-data leakage before it is sent.")


if __name__ == "__main__":
    raise SystemExit(main())
