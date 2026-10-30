# Ghost Data Still Exists audit agent

## Run

From the repository root, run:

```bash
python code/main.py
```

This reads the participant-facing CSV files and evidence paths from `dataset/` and writes `output.csv` at the repository root. It uses the Python standard library. PDF extraction uses PyMuPDF when installed; screenshot OCR uses Pillow and pytesseract plus a local Tesseract executable when available. Missing optional media tools are skipped safely.

Useful validation and evaluation commands:

```bash
python code/main.py --validate
python code/main.py --evaluate-sample
python code/evaluation/main.py
```

The sample-output file is opened only by the evaluation path. The prediction path never reads sample or expected labels.

## Approach

The program resolves a request email to a stable user ID, reconstructs current and historical identifiers known by `audit_at`, and requires both the evidence artifact's manifest capture time and the record's observation time to be at or before that cutoff. It reads SQL snapshots into isolated in-memory SQLite databases, traverses nested JSON exports with service context, parses key/value and pipe-delimited logs, joins related log events by trace ID, extracts PDF text, and attempts OCR on supplied images. It matches full scalar identifiers (including email hashes, phone numbers, and stable IDs) and applies the supplied deletion policy to categorized records.

`INCOMPLETE` results contain evidence-backed findings, ordered future remediation, and future verification. `COMPLETE` results contain only evidence-backed verification. A non-deletion request returns `NOT_APPLICABLE` and `[]`. Results are deterministic and use the required operation ordering.

## Input schemas and evidence formats inspected

- `deletion_requests.csv` / `sample_deletion_requests.csv`: `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text`
- `user_identities.csv`: `user_id,name,email,phone,email_hash,updated_at`
- `user_audit_log.csv`: `audit_id,user_id,event_time,field_name,old_value,new_value`
- `system_activity.csv`: `activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details`
- `deletion_rules.csv`: `rule_id,data_category,condition,required_action`
- `evidence_files.csv`: `file_id,file_path,origin,captured_at`
- Output: `case_id,deletion_status,steps_json`
- Evidence inventory: 94 files comprising 24 SQL snapshots, 28 JSON exports, 26 logs, 4 PDFs, 11 PNG screenshots, and 1 text handover record.

## Transcript requirements

The repository-root `log.txt` follows `AGENTS.md`: append-only session start and per-turn records with `User Prompt`, `Agent Response Summary`, `Actions`, and `Context`. Do not add secrets or private personal data. The log file is submitted separately as the `chat_transcript`; it is not part of `code.zip`.

## Limitations

The system is deterministic, uses no hosted model, and does not execute remediation. Public-sample results are reported separately from prediction. Rare multilingual phrasing, optional PDF/OCR dependencies, incomplete source coverage, ambiguous records, and evidence structures not represented in this corpus can reduce accuracy. Public-sample status accuracy is 32/32 and exact row accuracy is 17/32 (53.1%); the remediation plan and evidence links should be reviewed before relying on them.
