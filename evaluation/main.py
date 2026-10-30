"""Reproducible public-sample and synthetic edge-case evaluation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
import main as agent  # noqa: E402


def custom_cases() -> list[dict[str, object]]:
    # Case 1: a request for an export is not deletion authorization.
    not_deletion = not agent.authorizes_deletion("Please export my data and send me a copy.")
    # Case 2: deletion intent in Japanese is recognized despite CJK word boundaries.
    multilingual = agent.authorizes_deletion("このアカウントの削除をお願いします。")
    # Case 3: a late-created evidence file is unavailable even if its payload
    # claims that an underlying record was observed before the cutoff.
    cutoff = agent.parse_time("2026-09-01T00:00:00Z")
    late_artifact = {"available_at": "2026-09-02T00:00:00Z", "observed_at": "2026-08-31T00:00:00Z"}
    future_excluded = cutoff is not None and not agent.evidence_at_cutoff(late_artifact, cutoff)
    # Case 4: the service context wins over generic fields such as `email`.
    service_routing = agent.classify("generic_trace", {"service": "analytics_platform", "email": "x@example.test"}) == (
        "analytics_platform", "ANALYTICS_PROFILE")

    users = {"user_test": {"user_id": "user_test"}}
    ids = {"user_test": {"user_test", "test@example.test"}}
    case = {"case_id": "synthetic_trace", "email": "test@example.test", "requested_at": "2026-08-31T00:00:00Z",
            "reported_status": "NOT_STARTED", "reported_at": "", "audit_at": "2026-09-01T00:00:00Z",
            "request_text": "Please delete my account."}
    trace_evidence = [
        {"file_id": "evidence_synthetic", "available_at": "2026-08-31T00:00:00Z", "observed_at": "2026-08-31T00:00:00Z",
         "system": "account_service", "category": "USER_PROFILE",
         "row": {"resource_id": "line_1", "event": "profile_lookup_started", "lookup_key": "test@example.test", "trace_id": "trace-1"}},
        {"file_id": "evidence_synthetic", "available_at": "2026-08-31T00:00:00Z", "observed_at": "2026-08-31T00:00:00Z",
         "system": "account_service", "category": "USER_PROFILE",
         "row": {"resource_id": "account_test", "event": "profile_lookup_completed", "rows": "1", "trace_id": "trace-1"}},
    ]
    trace_status, trace_steps = agent.audit_case(case, users, ids, trace_evidence, [])
    trace_join = trace_status == "INCOMPLETE" and any(
        x["resource_id"] == "account_test" and x["operation"] == "REPORT_REMAINING_RECORD" for x in trace_steps)

    tombstone_evidence = [{"file_id": "evidence_synthetic", "available_at": "2026-08-31T00:00:00Z",
                           "observed_at": "2026-08-31T00:00:00Z", "system": "identity_service",
                           "category": "ACCOUNT_TOMBSTONE",
                           "row": {"resource_id": "tombstone_test", "subject_reference": "user_test",
                                   "name": "Test User", "email": "test@example.test", "phone": None,
                                   "email_hash": None, "_table": "deleted_customer_references"}}]
    tombstone_status, tombstone_steps = agent.audit_case(case, users, ids, tombstone_evidence, [])
    tombstone_redact = tombstone_status == "INCOMPLETE" and any(
        x["operation"] == "REDACT_RECORD" for x in tombstone_steps) and not any(
        x["operation"] == "DELETE_RECORD" for x in tombstone_steps)
    return [
        {"name": "export-only request", "passed": not_deletion, "expected": "NOT_APPLICABLE intent"},
        {"name": "Japanese deletion request", "passed": multilingual, "expected": "deletion authorized"},
        {"name": "post-cutoff artifact with earlier payload timestamp", "passed": future_excluded, "expected": "artifact excluded"},
        {"name": "service-aware classification", "passed": service_routing, "expected": "analytics event is not an email log"},
        {"name": "trace-linked lookup result", "passed": trace_join, "expected": "completed lookup is tied to its subject by trace id"},
        {"name": "account tombstone policy", "passed": tombstone_redact, "expected": "retain stable reference and redact direct identifiers"},
    ]


def main() -> None:
    sample = agent.evaluate()
    cases = custom_cases()
    print(json.dumps({"public_sample": sample, "custom_cases": cases,
                      "custom_cases_passed": sum(bool(x["passed"]) for x in cases)}, indent=2))


if __name__ == "__main__":
    main()
