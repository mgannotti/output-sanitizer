---
name: output-sanitizer
description: Check an outbound draft — email, Teams message, channel post, meeting body — for private-data leakage before it is sent, covering credentials, sensitivity labels, schedule and travel disclosure, third-party contact details, internal hostnames, local paths, and unfilled placeholders, then emit a redacted copy. Trigger when the user says "/output-sanitizer", "check this before I send it", "is this safe to send externally", "scrub this draft", "did I leak anything", or before any automation transmits content to another person.
---

# Output Sanitizer

Pre-send leakage check. The last gate between a draft and a recipient.

## When to use this

Before any external send, before any automation transmits content, and whenever a
draft was assembled from private context — mail, calendar, chat, or internal files.

## Inputs

Either a plain `.txt` / `.md` draft, or JSON with a `body` plus optional `to`, `cc`,
`bcc`, and `subject`. **Prefer JSON** — recipient-relative checks only work when the
recipient list is known.

## How to run it

```
python scripts/output_sanitizer.py \
  --input <draft.json> \
  --outdir out/output-sanitizer
```

- `--allow-contact a@x.test b@y.test` — addresses that may legitimately appear in the body.
- `--require-recipients` — flag drafts that declare no recipient list.
- `--no-redacted-copy` — report only.
- `--fail-on block` — exit non-zero on a blocking leak.

## What it detects

Blocking: `OS001` credential material (key formats and `key=value` patterns);
`OS004` sensitivity label leakage — a classification marker means the content behind it
is classified too.

High: `OS002` private schedule, travel, health, or family disclosure; `OS003` third-party
contact details not on the recipient list; `OS005` internal hosts, private IP ranges, and
personal SharePoint URLs.

Medium: `OS006` references to a private conversation the recipient was not part of;
`OS008` local filesystem paths that expose your username and machine layout;
`OS009` unfilled template placeholders; `OS010` large quoted history blocks.

## The redacted copy

`out/.../output-sanitizer.redacted.txt` has every detected span replaced with a typed
marker such as `[REDACTED-CREDENTIAL]` or `[REDACTED-PRIVATE]`, with surrounding prose
intact. Use it as the starting point for the corrected draft.

## How to read the result

Verdict `block` means do not send as written. `review` means a human must decide.
`pass` means nothing known matched — it is **not** permission to send.

## Limits — state these when you report

- Pattern-based. Novel secret formats and paraphrased disclosures will be missed.
- Without a recipient list, third-party disclosure cannot be evaluated.
- The tool cannot judge whether a fact is appropriate to share, only whether it looks
  private. Judgement stays with the sender.

## Guardrails

Never sends anything. Never resolves an address. No network. No cloud writes. This
skill is deliberately incapable of being the thing that transmits.
