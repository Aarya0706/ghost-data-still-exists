# Evaluation report

## Method

Predictions were produced using only the participant-facing `dataset/` files. The sample answer file is loaded only by `code/evaluation/main.py`; the prediction path never reads it. All 32 public sample requests were compared field by field. Six synthetic edge cases created for this solution test intent, temporal cutoffs, service routing, trace joins, and tombstone policy.

## Results

| Measure | Result |
|---|---:|
| Public sample case status accuracy | 32 / 32 = 100.00% |
| Exact output row accuracy (status and full steps array) | 17 / 32 = 53.13% |
| Exact step sequence accuracy | 17 / 32 = 53.13% |
| Step-position accuracy | 75.65% |
| Field accuracy across compared step positions | 82.75% |
| Synthetic custom cases passed | 6 / 6 |

“Case accuracy” means the predicted status matches. “Row accuracy” requires both status and the entire ordered steps array to match exactly. Step-position accuracy counts an aligned step only when all seven fields match. Field accuracy checks each of the seven fields independently by array position; omitted or extra positions count as incorrect.

## Custom evaluation cases

1. **Export-only request:** “Please export my data and send me a copy.” Expected: no deletion authorization (`NOT_APPLICABLE` intent). Passed.
2. **Japanese deletion request:** “このアカウントの削除をお願いします。” Expected: deletion authorization. Passed.
3. **Late-captured artifact:** a file captured after the audit cutoff is excluded even if its embedded record timestamp is earlier. Passed.
4. **Service-aware classification:** an analytics trace with an email field remains an analytics record rather than being misclassified as email delivery. Passed.
5. **Trace-linked lookup:** a completed result is connected to a directly identified lookup using a shared trace ID. Passed.
6. **Account tombstone:** a tombstone with direct identifiers is retained and redacted instead of deleted. Passed.

## Failures found and improvements made

- Initial evidence loading resolved manifest paths against the wrong directory, yielding no evidence. The loader now resolves manifest paths relative to `dataset/` and reads all 94 manifested files.
- SQL snapshots can store rows inside a `record_json` field. Those payloads are now parsed and classified using their source system and collection.
- JSON bundles nest collections and per-system snapshots. The reader now carries the service context into each record instead of mistaking container names or generic fields for service types.
- Handover text uses pipe-delimited records; that format is now parsed into timestamps, systems, resource IDs, categories, and states.
- Evidence is now excluded when either its manifest capture time or embedded observation time is after `audit_at`; this fixed future-artifact leakage.
- Related log lines are joined through trace IDs so a completed resource lookup can be evaluated alongside the matching request key. Started events do not independently prove resource state.
- Tombstones, contact lookups, and retention categories now follow their supplied policies before generic result handling.
- Status accuracy is perfect on the small public sample, but exact row and sequence accuracy remain low. The solution still misses or over-reports some evidence/resource links and needs review before operational use.

## Limits

This is a deterministic heuristic baseline, not a production deletion system. It does not perform changes in Northstar systems. PDF extraction and screenshot OCR depend on local optional tools; unreadable images or evidence formats may be missed. The public sample has only 32 cases and does not establish accuracy on the 518-request evaluation set. No hidden labels were available or used.

## Round 3 audit and fixes (against the full dataset and public sample answers)

Diffing predictions with `sample_output.csv` (evaluation only) showed systematic gaps. Fixes made:

- **Placeholder resource IDs removed.** Log-line and OCR/PDF line placeholders (`line_17`, `<file>_<n>`) were reported as real resources. They are positions in an artifact, not system resources, and are now ignored. This removed large amounts of noise (one case had 27 steps against 5 expected).
- **Event logs are judged by event time, not export capture time.** A log exported after `audit_at` still contains earlier events; excluding the whole file hid real evidence. Snapshots keep the capture-time rule. Event lines before `requested_at` are treated as history of an earlier lookup and ignored.
- **Replica systems map to their base service** (`support_replica` -> `support_platform`).
- **Active data flows cite the evidence file** that shows the resource rather than an `activity_id`, when such a file exists.
- **Primary account record**: when lookups do not surface it, the single account deletion performed within 15 minutes of `reported_at` is used and absence is cited from an account snapshot.
- **PDF extraction** falls back to pypdf or `pdftotext` when PyMuPDF is missing, so PDF evidence is no longer silently skipped.

## Round 4 fixes

- **Log parsing was broken for most formats.** Structured JSON logs (`<timestamp> {json}`), syslog, cloud-runtime exports with escaped quotes, bracketed application traces and pipe-delimited operations streams were not parsed into fields, so audit-record and lookup events were invisible. All five formats now parse, with trace IDs and event names extracted.
- **PDFs are one document record**, identified by the resource ID printed in them (for example `support_001`), instead of one pseudo-resource per line.
- **Later observations of a resource tied to the subject** (404, nulled, redacted or anonymized rows) are now linked to it. A snapshot captured after `audit_at` may establish who owns a resource, but never its state.
- **Preference for evidence the auditor had at `audit_at`** when several artifacts show the same resource.
- **Replica system names** resolve against the known system list.
- Full-dataset effect: COMPLETE rows with no verification steps fell from 37 to 14.

## Round 5: joint account attribution

The workflow log lists every account deletion for every requester, so a record cannot be tied to a person by timing alone. Cases and deletions are now matched jointly: a deletion qualifies for a case when its result agrees with the case's reported status, it falls shortly before `reported_at`, and it follows the request. A deletion wanted by only one case, or the only option for a case, is assigned; ambiguous ones are left unassigned rather than guessed. On the public sample every assigned account was correct (19 of 32 cases resolved, 0 wrong). Proposed analytics-record attribution with the same method was tested and rejected: it produced wrong and extra steps (4 correct, 1-3 wrong, 2-4 spurious) and is not used.

## Round 6 fixes

- **Whole-token identifier matching.** A name such as "jonas berg" no longer matches "Jonas Berglund", which created a false search-index record and false remediation steps.
- **Retained audit records tied by a later snapshot.** A security audit record that a post-`audit_at` snapshot attributes to the subject is retained by policy, so it was already present and is now verified as present.
- **Support messages and analytics profiles reported with `subject_reference` or an IDENTIFIABLE result** are now treated as exposed (redact / anonymize) instead of being ignored.

## Known remaining failures (not fixed)

- Retained security audit records (`VERIFY_RECORD_PRESENT`) are missed in 7 of 32 sample cases.
- Anonymized analytics records in COMPLETE cases (`VERIFY_RECORD_ANONYMIZED`) are missed: these are linked to the subject by deletion-worker activity, not by identifier.
- Some support attachments and policy-driven redact/anonymize findings are missed or over-reported.
- In the full run, 14 COMPLETE rows still have no verification steps. These are the least trustworthy rows: no evidence was found, which is not proof of deletion.
- Matching an account to a person by time alone is ambiguous when several deletions run concurrently; this is why that heuristic is only a fallback.

- Resources with no identifiers in any artifact (nulled analytics profiles) can only be tied to a person through the deletion-worker activity timeline, which is shared with decoy cases; these are still missed.
