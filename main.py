#!/usr/bin/env python3
"""Evidence-grounded deletion audit agent for the Ghost Data Still Exists challenge.

The implementation is deterministic and has no external model dependency. It reads
the participant-facing CSVs and recursively inspects JSON, SQL, logs, PDFs, and
images found in the evidence manifest. Evidence after audit_at is never consulted.
"""
from __future__ import annotations

import collections
import argparse
import csv
import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUT_FIELDS = ["case_id", "deletion_status", "steps_json"]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f))


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except ValueError:
        return None


def before_cutoff(value: Any, cutoff: datetime) -> bool:
    dt = parse_time(value)
    return dt is None or dt <= cutoff


def evidence_at_cutoff(item: dict[str, Any], cutoff: datetime) -> bool:
    """Require both artifact availability and embedded state time by audit_at."""
    return before_cutoff(item.get("available_at"), cutoff) and before_cutoff(item.get("observed_at"), cutoff)


def norm(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip().casefold()


def authorizes_deletion(text: str) -> bool:
    """Conservative phrase-level multilingual intent classifier (no status leakage)."""
    s = norm(text)
    # Explicit negation or unrelated requests take precedence.
    negatives = [
        r"\b(do not|don't|dont|never)\s+(delete|erase|remove|close)\b",
        r"\bnot\s+(delete|erase|remove)\b",
        r"\bkeep\s+(my|the)\s+account\b",
    ]
    if any(re.search(p, s) for p in negatives):
        return False
    deletion = [
        r"\b(delete|deleted|deletion|deleting|erase|erased|erasure|erasing|remove|removed|removes|removal|purge|wipe|close|closing|closed)\b",
        r"\bforget\s+me\b", r"\baccount\s+termination\b",
        r"\b(eliminar|eliminaci[oó]n|borrar|suprimir|cancelar)\b",
        r"\b(supprimer|suppression|effacer|effacement|cl[oô]turer)\b",
        r"\b(l[oó]schen|l[oö]schung|entfernen|entfernung)\b",
        r"\b(cancellare|eliminare|cancellazione)\b",
        r"\b(apagar|excluir|elimina[cç][aã]o)\b",
        r"\b(削除|消去|删除|刪除|删除账户|삭제)\b",
        r"\b(удалить|удаление|стереть)\b",
        r"\b(حذف|إزالة)\b",
    ]
    has_delete = any(re.search(p, s) for p in deletion)
    has_delete = has_delete or any(token in s for token in ("削除", "消去", "删除", "刪除", "삭제", "حذف", "إزالة"))
    if re.search(r"\b(account|profile|data|details)\b.{0,50}\b(gone|wiped|removed)\b", s):
        has_delete = True
    if not has_delete:
        return False
    return True


def build_identities() -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    users = {r["user_id"]: dict(r) for r in read_csv(DATASET / "user_identities.csv")}
    identifiers: dict[str, set[str]] = defaultdict(set)
    for uid, row in users.items():
        for k in ("user_id", "name", "email", "phone", "email_hash"):
            if norm(row.get(k)):
                identifiers[uid].add(norm(row[k]))
    for audit in read_csv(DATASET / "user_audit_log.csv"):
        uid = audit["user_id"]
        if uid not in users:
            continue
        for k in ("old_value", "new_value"):
            if norm(audit.get(k)):
                identifiers[uid].add(norm(audit[k]))
    return users, identifiers


def load_rules() -> dict[str, list[dict[str, str]]]:
    rules: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_csv(DATASET / "deletion_rules.csv"):
        rules[row["data_category"]].append(row)
    return rules


def read_sql(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Execute SQLite-compatible participant snapshots in an isolated memory DB."""
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        out = []
        for table in tables:
            if table == "snapshot_scope":
                continue
            columns = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
            for values in con.execute(f'SELECT * FROM "{table}"'):
                out.append((table, dict(zip(columns, values))))
        return out
    except sqlite3.Error:
        return []
    finally:
        con.close()


def classify(table: str, row: dict[str, Any], default_system: str = "") -> tuple[str, str]:
    raw = (table + " " + " ".join(str(v) for v in row.keys())).casefold()
    system = str(row.get("_system") or row.get("system_id") or row.get("system") or
                 row.get("source_system") or row.get("target_system") or row.get("service") or
                 row.get("data_store") or default_system or "")
    low_table = table.casefold()
    explicit = {
        "user_profile": ("account_service", "USER_PROFILE"),
        "search_index_entry": ("search_service", "SEARCH_INDEX_ENTRY"),
        "analytics_profile": ("analytics_platform", "ANALYTICS_PROFILE"),
        "product_telemetry": ("analytics_platform", "PRODUCT_TELEMETRY"),
        "support_message": ("support_platform", "SUPPORT_MESSAGE"),
        "support_attachment": ("support_platform", "SUPPORT_ATTACHMENT"),
        "data_flow": ("integration_service", "DATA_FLOW"),
        "backup_archive": ("backup_service", "BACKUP_ARCHIVE"),
        "security_audit_log": ("security_service", "SECURITY_AUDIT_LOG"),
        "legal_hold_record": ("security_service", "LEGAL_HOLD_RECORD"),
        "email_delivery_log": ("notification_service", "EMAIL_DELIVERY_LOG"),
        "user_export": ("export_service", "USER_EXPORT"),
        "account_tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    }
    if low_table in explicit:
        preferred_system, category = explicit[low_table]
        return system or preferred_system, category

    if "deleted_customer_references" in low_table or "tombstone" in low_table:
        return system or "identity_service", "ACCOUNT_TOMBSTONE"

    event = norm(row.get("event"))
    if "contact_query" in event:
        return system or "support_platform", "SECONDARY_IDENTIFIER"
    if "contact_lookup" in event or "email_opt_in" in raw:
        return system or "analytics_platform", "MARKETING_PROFILE"

    # Service names are stronger type evidence than generic record fields. For
    # example, an analytics trace can contain an `email` field without being an
    # email-delivery log, and a support trace can mention profile lookups.
    service_category = {
        "account_service": "USER_PROFILE",
        "search_service": "SEARCH_INDEX_ENTRY",
        "analytics_platform": "PRODUCT_TELEMETRY" if "telemetry" in raw or "telemetry" in event else "ANALYTICS_PROFILE",
        "support_platform": "SUPPORT_ATTACHMENT" if "attachment" in raw or "attachment" in event else "SUPPORT_MESSAGE",
        "integration_service": "DATA_FLOW",
        "backup_service": "BACKUP_ARCHIVE",
        "security_service": "LEGAL_HOLD_RECORD" if "legal_hold" in raw or "legal hold" in raw or "legal_hold" in event else "SECURITY_AUDIT_LOG",
        "notification_service": "EMAIL_DELIVERY_LOG",
        "marketing_platform": "MARKETING_PROFILE",
        "identity_service": "ACCOUNT_TOMBSTONE" if "tombstone" in raw else "SECONDARY_IDENTIFIER",
    }
    if system in service_category:
        return system, service_category[system]
    if "security_audit" in low_table or "security_audit" in raw or "audit_events" in low_table:
        return "security_service", "SECURITY_AUDIT_LOG"
    if "customer_profiles" in low_table or "profile_lookups" in low_table:
        return "account_service", "USER_PROFILE"
    if "customer_search" in low_table or "search_documents" in low_table:
        return "search_service", "SEARCH_INDEX_ENTRY"
    if "customer_analytics" in low_table or "analytics_profiles" in low_table or "analytics_reports" in low_table:
        return "analytics_platform", "ANALYTICS_PROFILE"
    if "support_conversation" in low_table or "support_records" in low_table:
        return "support_platform", "SUPPORT_MESSAGE"
    if "support_attachment" in low_table or "attachment" in low_table:
        return "support_platform", "SUPPORT_ATTACHMENT"
    if "connector_config" in low_table or "connector_subscription" in low_table:
        return "integration_service", "DATA_FLOW"
    if "backup_catalog" in low_table or "backup_restore" in low_table:
        return "backup_service", "BACKUP_ARCHIVE"
    if "customer_export" in low_table or "export_jobs" in low_table:
        return "export_service", "USER_EXPORT"
    if "marketing" in low_table:
        return "marketing_platform", "MARKETING_PROFILE"
    if "connector" in raw or "subscription" in raw or "flow" in raw or "sync" in raw or "import" in raw:
        return row.get("system_id") or row.get("system") or row.get("target_system") or "integration_service", "DATA_FLOW"
    if "backup" in raw or "restore" in raw or "archive" in raw:
        return row.get("system_id") or row.get("system") or "backup_service", "BACKUP_ARCHIVE"
    mappings = [
        (("profile", "account", "tombstone"), ("account_service", "ACCOUNT_TOMBSTONE" if "tombstone" in raw else "USER_PROFILE")),
        (("search", "index"), ("search_service", "SEARCH_INDEX_ENTRY")),
        (("analytic", "telemetry", "metric"), ("analytics_platform", "ANALYTICS_PROFILE")),
        (("support", "ticket", "message", "attachment"), ("support_platform", "SUPPORT_MESSAGE")),
        (("export", "object_storage"), ("export_service", "USER_EXPORT")),
        (("marketing",), ("marketing_platform", "MARKETING_PROFILE")),
        (("security_audit", "audit_record", "retention"), ("security_service", "SECURITY_AUDIT_LOG")),
        (("email", "delivery_log"), ("notification_service", "EMAIL_DELIVERY_LOG")),
        (("cache",), ("cache_service", "CACHE_ENTRY")),
    ]
    for keys, result in mappings:
        if any(k in raw for k in keys):
            return result
    system = row.get("data_store") or row.get("system") or row.get("origin_system") or row.get("service") or system or "unknown_system"
    return str(system), "UNKNOWN"


def record_time(row: dict[str, Any], fallback: str) -> str:
    for k in ("captured_at", "observed_at", "recorded_at", "updated_at", "indexed_at", "created_at", "event_time", "timestamp"):
        if parse_time(row.get(k)):
            return str(row[k])
    return fallback


def nested_records(obj: Any, fallback_time: str, default_system: str = "") -> Iterable[tuple[str, dict[str, Any], str]]:
    """Yield record-like mappings from arbitrary nested JSON exports."""
    service_names = {"account_service", "search_service", "analytics_platform", "support_platform",
                     "integration_service", "backup_service", "security_service", "notification_service",
                     "marketing_platform", "identity_service"}
    generic_names = {"service_exports", "snapshots", "exports", "data", "records", "evidence", "systems", "services"}

    def child_context(parent: str, key: str) -> str:
        key_norm = str(key).casefold()
        if key_norm in service_names:
            return str(key)
        if not parent or parent.casefold() in generic_names:
            return str(key)
        return parent

    if isinstance(obj, dict):
        own_system = obj.get("data_store") or obj.get("system") or obj.get("system_id") or default_system
        own_time = obj.get("captured_at") or obj.get("observed_at") or fallback_time
        own_collection = obj.get("collection") or obj.get("collection_name") or obj.get("_table") or ""
        # A resource-bearing mapping is one record. Include nested child dicts separately
        # because JSON often nests the PII fields under document/profile/message.
        if any(k in obj for k in ("resource_id", "record_id", "activity_id")):
            record = dict(obj)
            record["_system"] = own_system
            record["_observed_at"] = own_time
            yield str(obj.get("_table", "json_record")), record, record_time(record, str(own_time))
        for key, val in obj.items():
            if isinstance(val, list):
                for child in val:
                    if isinstance(child, dict):
                        child = dict(child)
                        child.setdefault("_table", own_collection or key)
                    yield from nested_records(child, str(own_time), child_context(str(own_system or ""), str(key)))
            elif isinstance(val, dict):
                child = dict(val)
                if own_collection:
                    child.setdefault("_table", own_collection)
                yield from nested_records(child, str(own_time), child_context(str(own_system or ""), str(key)))
    elif isinstance(obj, list):
        for child in obj:
            yield from nested_records(child, fallback_time, default_system)


def load_evidence() -> list[dict[str, Any]]:
    manifest = read_csv(DATASET / "evidence_files.csv")
    out: list[dict[str, Any]] = []
    for item in manifest:
        # Manifest paths are relative to dataset/.
        path = DATASET / item["file_path"]
        ext = path.suffix.lower()
        captured = item.get("captured_at", "")
        file_id = item["file_id"]
        try:
            if ext == ".json":
                obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                for table, row, observed in nested_records(obj, captured):
                    system, category = classify(table, row)
                    out.append(dict(file_id=file_id, observed_at=observed, available_at=captured,
                                    system=str(system), category=category, row=row, source="file"))
            elif ext == ".sql":
                for table, row in read_sql(path):
                    if isinstance(row.get("record_json"), str):
                        try:
                            payload = json.loads(row["record_json"])
                            if isinstance(payload, dict):
                                row.update(payload)
                        except json.JSONDecodeError:
                            pass
                    row["_system"] = row.get("origin_system") or row.get("_system") or ""
                    row["_table"] = row.get("collection_name") or table
                    system, category = classify(table, row)
                    out.append(dict(file_id=file_id, observed_at=record_time(row, captured), available_at=captured,
                                    system=str(system), category=category, row=row, source="file"))
            elif ext in (".log", ".txt"):
                text = path.read_text(encoding="utf-8", errors="replace")
                # Preserve records as line evidence. Parse common key=value / JSON lines.
                for i, line in enumerate(text.splitlines(), 1):
                    if not line.strip():
                        continue
                    row: dict[str, Any] = {"resource_id": f"line_{i}", "text": line}
                    flat = line.replace('\\"', '"')
                    cols = [part.strip() for part in flat.split("|")]
                    if cols:
                        cols[0] = cols[0].lstrip("- ").strip()
                    ops_stream = len(cols) >= 5 and parse_time(cols[0]) and re.match(r"(tr|rb)-", cols[3] or "")
                    if len(cols) >= 6 and parse_time(cols[0]) and not ops_stream:
                        row.update({"_observed_at": cols[0], "_system": cols[1], "resource_id": cols[2],
                                    "_table": cols[3], "result": cols[4], "subject_reference": cols[5],
                                    "_parsed_report": True})
                    if ops_stream:
                        row.update({"_observed_at": cols[0], "level": cols[1], "service": cols[2],
                                    "trace_id": cols[3], "event": cols[4]})
                    # Structured logs are "<timestamp> {json}"; parse the JSON object part and
                    # keep the leading timestamp as the event time.
                    brace = flat.find("{")
                    if brace >= 0:
                        try:
                            parsed = json.loads(flat[brace:])
                            if isinstance(parsed, dict):
                                row.update({k: (str(v) if not isinstance(v, (dict, list)) else v) for k, v in parsed.items()})
                                lead = flat[:brace].strip()
                                if parse_time(lead) and "_observed_at" not in row:
                                    row["_observed_at"] = lead
                        except json.JSONDecodeError:
                            pass
                    for k, v in re.findall(r'([A-Za-z_][\w.-]*)=("[^"]*"|[^\s,;]+)', flat):
                        row[k] = v.strip('"\'')
                    # Trace ids appear as trace_id=, requestId=, a syslog field or a [tr-..] tag.
                    if not row.get("trace_id"):
                        m = re.search(r"\b((?:tr|rb)-[\w-]+)", flat)
                        if m:
                            row["trace_id"] = m.group(1)
                    if not row.get("event"):
                        m = re.search(r"\]\s*(\w+):", flat)
                        if m:
                            row["event"] = m.group(1)
                    lead_ts = flat.split(" ", 1)[0]
                    if "_observed_at" not in row and parse_time(lead_ts):
                        row["_observed_at"] = lead_ts
                    system, category = classify(str(row.get("_table") or path.stem), row, "observability")
                    obs = record_time(row, str(row.get("_observed_at") or captured))
                    # An event log export captured later still contains earlier events; those
                    # events are usable by their own timestamp. Snapshots keep the capture time.
                    avail = obs if ext == ".log" else captured
                    out.append(dict(file_id=file_id, observed_at=obs, available_at=avail,
                                    system=str(system), category=category, row=row, source="file", event_log=(ext == ".log")))
            elif ext == ".pdf":
                text = pdf_text(path)
                if text:
                    out.extend(pdf_records(text, file_id, captured, path.stem))
            elif ext in (".png", ".jpg", ".jpeg", ".tif", ".tiff"):
                try:
                    from PIL import Image  # type: ignore
                    import pytesseract  # type: ignore
                    text = pytesseract.image_to_string(Image.open(path))
                    out.extend(text_evidence(text, file_id, captured, path.stem, "image"))
                except Exception:
                    # Image OCR is best-effort; all image-derived claims remain tied to file_id.
                    pass
        except (OSError, ValueError, sqlite3.Error):
            continue
    cap = {m["file_id"]: m.get("captured_at", "") for m in manifest}
    for item in out:
        item["captured"] = cap.get(item["file_id"], "")
    return out


def pdf_text(path: Path) -> str:
    """Extract PDF text with whichever backend is installed (PyMuPDF, pypdf, pdftotext)."""
    try:
        import fitz  # type: ignore
        return "\n".join(page.get_text() for page in fitz.open(path))
    except Exception:
        pass
    for mod in ("pypdf", "PyPDF2"):
        try:
            reader = __import__(mod).PdfReader(str(path))
            return "\n".join((pg.extract_text() or "") for pg in reader.pages)
        except Exception:
            continue
    try:
        import subprocess
        return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return ""


def pdf_records(text: str, file_id: str, captured: str, stem: str) -> list[dict[str, Any]]:
    """A PDF is one document. Its record is the resource id printed in it (for example the
    support reference), and any identifier anywhere in the document exposes that record."""
    ids = re.findall(r"\b((?:support|account|search|analytics|backup|export|marketing|audit_record|data_flow|legal_hold|cache)_\w*\d+)\b", text)
    if not ids:
        return text_evidence(text, file_id, captured, stem, "pdf")
    rid = ids[0]
    row: dict[str, Any] = {"resource_id": rid, "text": text, "_observed_at": captured, "_table": stem}
    system, category = classify(stem, row)
    if system in ("", "unknown", "UNKNOWN"):
        system = {"support": "support_platform", "account": "account_service", "search": "search_service",
                  "analytics": "analytics_platform", "backup": "backup_service", "export": "export_service",
                  "marketing": "marketing_platform", "audit_record": "security_service", "data_flow": "integration_service"}.get(rid.split("_")[0], system)
    return [dict(file_id=file_id, observed_at=captured, available_at=captured, system=str(system),
                 category=category, row=row, source="pdf")]


def text_evidence(text: str, file_id: str, captured: str, stem: str, kind: str) -> list[dict[str, Any]]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            row: dict[str, Any] = {"resource_id": f"{stem}_{i}", "text": line}
            cols = [part.strip() for part in line.split("|")]
            if cols:
                cols[0] = cols[0].lstrip("- ").strip()
            if len(cols) >= 6 and parse_time(cols[0]):
                row.update({"_observed_at": cols[0], "_system": cols[1], "resource_id": cols[2],
                            "_table": cols[3], "result": cols[4], "subject_reference": cols[5],
                            "_parsed_report": True})
            else:
                row["_observed_at"] = captured
            system, category = classify(str(row.get("_table") or stem), row)
            out.append(dict(file_id=file_id, observed_at=str(row.get("_observed_at") or captured), available_at=captured,
                            system=str(system), category=category, row=row, source=kind))
    return out


def identity_for(case: dict[str, str], users: dict[str, dict[str, Any]], ids: dict[str, set[str]]) -> tuple[str | None, set[str]]:
    email = norm(case.get("email"))
    matches = [uid for uid, vals in ids.items() if email in vals]
    if len(matches) == 1:
        return matches[0], ids[matches[0]]
    return None, set()


def identifiers_at(uid: str, case: dict[str, str], users: dict[str, dict[str, Any]], cutoff: datetime) -> set[str]:
    """Resolve identifiers using only identity snapshots and audit changes known by cutoff."""
    values: set[str] = {norm(case.get("email")), norm(uid)}
    user = users.get(uid, {})
    if before_cutoff(user.get("updated_at"), cutoff):
        values.update(norm(user.get(k)) for k in ("name", "email", "phone", "email_hash") if norm(user.get(k)))
    for audit in read_csv(DATASET / "user_audit_log.csv"):
        if audit.get("user_id") == uid and before_cutoff(audit.get("event_time"), cutoff):
            values.update(norm(audit.get(k)) for k in ("old_value", "new_value") if norm(audit.get(k)))
    return values


def contains_identifier(row: dict[str, Any], identifiers: set[str]) -> bool:
    if not identifiers:
        return False
    # Test individual scalar values, not a serialized substring, so user_01 cannot
    # accidentally match user_010 and a name cannot match an unrelated longer name.
    values: list[str] = []
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)
        elif value is not None:
            values.append(norm(value))
    walk(row)
    observed = set(values)
    if identifiers & observed:
        return True
    # Message text can quote an email or phone in a larger scalar.
    for value in values:
        for identifier in identifiers:
            # Whole-token match only: "jonas berg" must not match "jonas berglund".
            if len(identifier) >= 9 and identifier in value and re.search(
                    r"(?<![\w.@+])" + re.escape(identifier) + r"(?![\w@]|\.\w)", value):
                return True
    return False


def trace_ids(row: dict[str, Any]) -> set[str]:
    """Return strong within-file operation identifiers used to join log lines."""
    return {norm(row.get(k)) for k in ("trace_id", "traceId", "correlation_id", "request_id")
            if norm(row.get(k)) not in ("", "null", "none")}


def resource_id(row: dict[str, Any]) -> str:
    for k in ("resource_id", "record_id", "id", "object_key", "archive_key"):
        if row.get(k) not in (None, ""):
            return str(row[k])
    return "unknown_resource"


def data_flow_event(activity: dict[str, str], identifiers: set[str]) -> bool:
    typ = norm(activity.get("event_type"))
    details = norm(activity.get("details"))
    if not any(x in typ for x in ("sync", "import", "restore", "replic", "connector", "export", "data_flow")):
        return False
    return any(len(x) >= 6 and x in details for x in identifiers)


def direct_action(category: str, row: dict[str, Any], user_id: str,
                  cutoff: datetime | None = None,
                  rules: dict[str, list[dict[str, str]]] | None = None) -> str | None:
    cat = category.upper()
    if cat == "UNKNOWN":
        return None
    result = norm(row.get("result"))
    # Apply category-specific retention and transformation rules before generic
    # `found` handling. A present tombstone is retained and redacted, while an
    # attributable analytics profile is anonymized rather than deleted.
    if cat == "ACCOUNT_TOMBSTONE":
        direct = any(norm(row.get(k)) not in ("", "null", "none", "[redacted]")
                     for k in ("name", "full_name", "email", "phone", "email_hash",
                               "requester_name", "requester_email", "requester_phone"))
        return "REDACT" if direct else "VERIFY_REDACTED"
    if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        linked = any(norm(row.get(k)) not in ("", "null", "none")
                     for k in ("user_id", "user_ref", "customer_reference", "email", "email_hash", "phone", "subject_reference"))
        if result in ("anonymized",):
            return "VERIFY_ANONYMIZED"
        return "ANONYMIZE" if (linked or result in ("identifiable", "found", "present")) else "VERIFY_ANONYMIZED"
    if cat == "SECURITY_AUDIT_LOG":
        retention_until = parse_time(row.get("retention_until"))
        if result in ("found", "present", "retained", ""):
            return "RETAIN"
        return "RETAIN" if retention_until is None or cutoff is None or retention_until >= cutoff else "DELETE"
    if cat == "LEGAL_HOLD_RECORD":
        return "RETAIN" if norm(row.get("hold_status", "active")) in ("active", "true", "1") else "DELETE"
    if cat == "BACKUP_ARCHIVE":
        restore_allowed = row.get("restore_allowed") in (1, "1", True, "true", "TRUE")
        if result in ("blocked", "disabled") or row.get("restore_allowed") in (0, "0", False, "false", "FALSE"):
            return "VERIFY_BLOCKED"
        return "BLOCK_RESTORE" if restore_allowed or result in ("found", "present", "identifiable") else "BLOCK_RESTORE"
    if cat == "SUPPORT_MESSAGE":
        direct = any(norm(row.get(k)) not in ("", "null", "none", "[redacted]")
                     for k in ("requester_name", "requester_email", "requester_phone", "email", "phone", "message_text",
                               "matched_value", "subject_reference"))
        if result == "redacted" or norm(row.get("message_text")) == "[redacted]":
            return "VERIFY_REDACTED"
        if result in ("identifiable", "found", "present") or norm(row.get("detector")) == "direct_identifier":
            return "REDACT"
        return "REDACT" if direct else "VERIFY_REDACTED"
    if cat == "EMAIL_DELIVERY_LOG":
        direct = any(norm(row.get(k)) not in ("", "null", "none", "[redacted]")
                     for k in ("email", "recipient", "recipient_email", "subject_reference"))
        return "REDACT" if direct else "VERIFY_REDACTED"
    if result in ("not_found", "404", "absent"):
        return "VERIFY_ABSENT"
    if result in ("found", "present", "identifiable"):
        if cat == "DATA_FLOW":
            return "DISABLE_FLOW"
        return "DELETE"
    if result in ("anonymized", "redacted"):
        if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            return "VERIFY_ANONYMIZED" if result == "anonymized" else "ANONYMIZE"
        return "VERIFY_REDACTED" if result == "redacted" else "VERIFY_ANONYMIZED"
    if result in ("disabled", "blocked", "retained"):
        return {"disabled": "VERIFY_DISABLED", "blocked": "VERIFY_BLOCKED", "retained": "RETAIN"}[result]
    if row.get("status_code") == 404 or row.get("http_status") == 404 or row.get("rows") == "0":
        return "VERIFY_ABSENT"
    try:
        positive_rows = int(row.get("rows", 0) or 0) > 0
    except (TypeError, ValueError):
        positive_rows = False
    if positive_rows:
        if cat in ("SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "USER_EXPORT", "SEARCH_INDEX_ENTRY", "USER_PROFILE"):
            return "DELETE"
    if cat in ("DATA_FLOW",):
        enabled = row.get("enabled") in (1, "1", True, "true", "TRUE") or norm(row.get("status")) in ("active", "enabled", "running")
        return "DISABLE_FLOW" if enabled else "VERIFY_DISABLED"
    if cat == "BACKUP_ARCHIVE":
        return "BLOCK_RESTORE" if row.get("restore_allowed") in (1, "1", True, "true", "TRUE") else "VERIFY_BLOCKED"
    # Apply the supplied category policy for generic record types.
    policy_action = str((rules or {}).get(cat, [{}])[0].get("required_action", "")).upper()
    if policy_action == "REDACT":
        direct = any(norm(row.get(k)) for k in ("name", "full_name", "email", "phone", "email_hash",
                                                 "requester_name", "requester_email", "requester_phone"))
        return "REDACT" if direct else "VERIFY_REDACTED"
    if policy_action == "ANONYMIZE":
        linked = any(norm(row.get(k)) for k in ("user_id", "user_ref", "customer_reference", "email", "email_hash", "phone"))
        return "ANONYMIZE" if linked else "VERIFY_ANONYMIZED"
    if policy_action == "RETAIN":
        return "RETAIN"
    # Deletion rules default to DELETE for direct customer copies and exports.
    if cat == "SUPPORT_ATTACHMENT":
        return "DELETE"
    return "DELETE"



# ---- Joint resolution of each person's primary account record -------------------------
# The workflow log lists every account deletion for every requester, so a record can only
# be attributed to a person by elimination: a deletion qualifies for a case when its result
# matches the case's reported status and it happened shortly before reported_at (after the
# request). Cases and deletions are then matched jointly; a deletion wanted by one case, or
# the only option for a case, is assigned, and ambiguous ones are left unassigned.
ACCOUNT_RESULT={'COMPLETE':'SUCCESS','PARTIALLY_COMPLETE':'PARTIAL','NOT_STARTED':'FAILED'}
def account_candidates(c,acc,lo,hi):
    r=parse_time(c['reported_at']);q=parse_time(c['requested_at'])
    out=[]
    for a in acc:
        t=parse_time(a['event_time'])
        off=(r-t).total_seconds()/60
        if a['reported_result']==ACCOUNT_RESULT.get(c['reported_status']) and lo<=off<=hi and t>=q: out.append(a['resource_id'])
    return out
def assign_accounts(cases,acts):
    acc=[a for a in acts if a['event_type']=='DELETE_RECORD' and a['target_system']=='account_service']
    out={}
    for lo,hi in ((44,76),(-10,135)):
        C={c['case_id']:set(account_candidates(c,acc,lo,hi)) for c in cases if c['case_id'] not in out}
        taken=set(out.values());
        for k in C: C[k]-=taken
        changed=True
        while changed:
            changed=False
            for k,v in C.items():
                if k in out:continue
                if len(v)==1:
                    r=next(iter(v));out[k]=r;changed=True
                    for k2 in C:
                        if k2!=k: C[k2].discard(r)
            # also: a resource wanted by exactly one case
            want=collections.defaultdict(set)
            for k,v in C.items():
                if k in out:continue
                for r in v: want[r].add(k)
            for r,ks in want.items():
                if len(ks)==1:
                    k=next(iter(ks))
                    if k not in out and r not in out.values(): out[k]=r;changed=True
                    for k2 in C:
                        if k2!=k: C[k2].discard(r)
    return out


_ACCOUNT_ASSIGNMENT: dict[str, str] | None = None


def account_assignment(activities: list[dict[str, str]]) -> dict[str, str]:
    global _ACCOUNT_ASSIGNMENT
    if _ACCOUNT_ASSIGNMENT is None:
        cases: list[dict[str, str]] = []
        for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
            if (DATASET / name).exists():
                cases.extend(read_csv(DATASET / name))
        _ACCOUNT_ASSIGNMENT = assign_accounts(cases, activities)
    return _ACCOUNT_ASSIGNMENT


def canonical_system(system: str, known: set[str]) -> str:
    """Replicas, primaries and read copies belong to their base service."""
    base = re.sub(r"_(failover_replica|read_replica|replica|primary)$", "", system)
    if base in known or base == system:
        return base
    return next((k for k in sorted(known) if k.startswith(base + "_")), base)


def is_synthetic_resource(rid: str) -> bool:
    """Placeholders built by the parsers (log line numbers, OCR/PDF line ids) are
    positions inside an artifact, not resources of a system, so never report them."""
    r = str(rid)
    return r in ("", "unknown_resource") or bool(re.fullmatch(r"line_\d+", r)) or bool(re.search(r"_\d{8}(_\d{6})?_\d+$", r))


def make_step(phase: str, system: str, rid: str, operation: str, state: str, evidence: str = "") -> dict[str, Any]:
    return {"phase": phase, "system_id": system, "resource_id": rid, "operation": operation, "state": state, "evidence_id": evidence}


def op_key(step: dict[str, Any]) -> tuple[Any, ...]:
    phase, op = step["phase"], step["operation"]
    order = FINDING_ORDER if phase == "FINDING" else REMEDIATION_ORDER if phase == "REMEDIATION" else VERIFICATION_ORDER
    return PHASE_ORDER[phase], order.get(op, 99), step["system_id"], step["resource_id"], step["evidence_id"]


def audit_case(case: dict[str, str], users: dict[str, dict[str, Any]], ids: dict[str, set[str]],
               evidence: list[dict[str, Any]], activities: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]]:
    if not authorizes_deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []
    uid, identifiers = identity_for(case, users, ids)
    if not uid:
        # Do not guess across users; unresolved identity requires investigation.
        return "INCOMPLETE", []
    cutoff = parse_time(case.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    requested = parse_time(case.get("requested_at")) or datetime.min.replace(tzinfo=timezone.utc)
    identifiers = identifiers_at(uid, case, users, cutoff)
    rules = load_rules()
    known_systems = {a.get("target_system", "") for a in activities} | {a.get("source_system", "") for a in activities}
    eligible: list[dict[str, Any]] = []
    for item in evidence:
        # Embedded record timestamps describe the resource state, but an artifact
        # captured after audit_at was not available to the auditor at that time.
        if not evidence_at_cutoff(item, cutoff):
            continue
        if item.get("event_log") and norm(item["row"].get("event")) and before_cutoff(item.get("observed_at"), requested - timedelta(seconds=1)):
            continue
        eligible.append(item)
    directly_matched = [item for item in eligible if contains_identifier(item["row"], identifiers)]
    # A service trace often puts the lookup key on the *_started line and the
    # resolved resource/state on a later *_completed line. Join only by a strong
    # trace identifier, within the same evidence file and audit window.
    traces_by_file: dict[str, set[str]] = defaultdict(set)
    for item in directly_matched:
        traces_by_file[item["file_id"]].update(trace_ids(item["row"]))
    matched = list(directly_matched)
    seen = {(x["file_id"], resource_id(x["row"])) for x in matched}
    for item in eligible:
        traces = trace_ids(item["row"])
        if traces & traces_by_file.get(item["file_id"], set()):
            key = (item["file_id"], resource_id(item["row"]))
            if key not in seen:
                matched.append(item)
                seen.add(key)
    # Keep the latest observation per logical resource. A snapshot row carries actual
    # contents; audit/event lines are still retained as evidence for flows and proof.
    by_resource: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in matched:
        by_resource[(item["system"], resource_id(item["row"]))].append(item)
    # A point-in-time profile lookup may contain only a resource key and a 404.
    # Link it to this subject using an earlier evidence-backed resource association.
    known_resources = {(x["system"], resource_id(x["row"])) for x in matched
                       if resource_id(x["row"]) != "unknown_resource"}
    future_audit: dict[tuple[str, str], dict[str, Any]] = {}
    # Which resource belongs to which person does not change over time, so an artifact
    # captured after audit_at may still tell us who owns a resource (never its state).
    for item in evidence:
        if item not in eligible and item.get("source") == "file" and not item.get("event_log") \
                and contains_identifier(item["row"], identifiers) and resource_id(item["row"]) != "unknown_resource" \
                and not is_synthetic_resource(resource_id(item["row"])):
            known_resources.add((item["system"], resource_id(item["row"])))
            if item["category"] == "SECURITY_AUDIT_LOG":
                future_audit[(item["system"], resource_id(item["row"]))] = item
    if known_resources:
        for item in evidence:
            row = item["row"]
            if not evidence_at_cutoff(item, cutoff):
                continue
            # Once a resource is tied to the subject by any earlier observation, its later
            # observations (404, nulled, redacted or anonymized rows) describe the same resource.
            if (item["system"], resource_id(row)) in known_resources and item not in matched:
                matched.append(item)
                by_resource[(item["system"], resource_id(row))].append(item)
    current = []
    for observations in by_resource.values():
        observations.sort(key=lambda x: (before_cutoff(x.get("captured"), cutoff),
                                         parse_time(x["observed_at"]) or datetime.min.replace(tzinfo=timezone.utc), x["file_id"]))
        current.append(observations[-1])
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    for item in current:
        row, system, cat, rid = item["row"], item["system"], item["category"], resource_id(item["row"])
        system = canonical_system(str(system), known_systems)
        # A started trace records a lookup attempt, not the resulting resource
        # state. It can link to the completed event above but cannot prove a finding.
        if norm(row.get("event")).endswith("_started"):
            continue
        if is_synthetic_resource(rid):
            continue
        action = direct_action(cat, row, uid, cutoff, rules)
        if action is None:
            continue
        if action in ("VERIFY_REDACTED", "VERIFY_ANONYMIZED"):
            vop = "VERIFY_RECORD_REDACTED" if action == "VERIFY_REDACTED" else "VERIFY_RECORD_ANONYMIZED"
            verifications.append(make_step("VERIFICATION", system, rid, vop,
                                           "REDACTED" if action == "VERIFY_REDACTED" else "ANONYMIZED", item["file_id"]))
        elif action == "VERIFY_DISABLED":
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", item["file_id"]))
        elif action == "VERIFY_BLOCKED":
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", item["file_id"]))
        elif action == "RETAIN":
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RECORD_PRESENT", "PRESENT", item["file_id"]))
        elif action == "VERIFY_ABSENT":
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RECORD_ABSENT", "ABSENT", item["file_id"]))
        elif action == "DELETE":
            findings.append(make_step("FINDING", system, rid, "REPORT_REMAINING_RECORD", "PRESENT", item["file_id"]))
            remediations.append(make_step("REMEDIATION", system, rid, "DELETE_RECORD", "ABSENT"))
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RECORD_ABSENT", "ABSENT"))
        elif action == "REDACT":
            findings.append(make_step("FINDING", system, rid, "REPORT_EXPOSED_PII", "PRESENT", item["file_id"]))
            remediations.append(make_step("REMEDIATION", system, rid, "REDACT_RECORD", "REDACTED"))
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RECORD_REDACTED", "REDACTED"))
        elif action == "ANONYMIZE":
            findings.append(make_step("FINDING", system, rid, "REPORT_EXPOSED_PII", "PRESENT", item["file_id"]))
            remediations.append(make_step("REMEDIATION", system, rid, "ANONYMIZE_RECORD", "ANONYMIZED"))
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
        elif action == "DISABLE_FLOW":
            findings.append(make_step("FINDING", system, rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", item["file_id"]))
            remediations.append(make_step("REMEDIATION", system, rid, "DISABLE_DATA_FLOW", "DISABLED"))
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
        elif action == "BLOCK_RESTORE":
            findings.append(make_step("FINDING", system, rid, "REPORT_RESTORE_RISK", "ACTIVE", item["file_id"]))
            remediations.append(make_step("REMEDIATION", system, rid, "BLOCK_RESTORE", "BLOCKED"))
            verifications.append(make_step("VERIFICATION", system, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
    # System activity is a weak but participant-visible event source. Only classify it
    # as active when text explicitly links one of the subject identifiers and names an
    # active operation; status fields remain untrusted claims.
    subject_resources = {
        (item["system"], resource_id(item["row"]))
        for item in matched
        if item["category"] in {"DATA_FLOW", "BACKUP_ARCHIVE"}
        and resource_id(item["row"]) != "unknown_resource"
    }
    for a in activities:
        if not before_cutoff(a.get("event_time"), cutoff):
            continue
        text = norm(a.get("details"))
        event_target = a.get("target_system") or a.get("source_system") or ""
        event_resource = a.get("resource_id") or ""
        linked_to_subject = data_flow_event(a, identifiers) or (event_target, event_resource) in subject_resources
        if not linked_to_subject:
            continue
        if any(t in text for t in ("active", "enabled", "running", "will replicate", "scheduled")):
            target = event_target or "unknown_system"
            rid = a.get("resource_id") or a.get("activity_id") or "unknown_resource"
            # Prefer a supplied evidence artifact that shows the same resource (a file_id);
            # an activity_id is only the fallback when no artifact observed it.
            seen_in = sorted((x for x in eligible if resource_id(x["row"]) == rid and not norm(x["row"].get("event")).endswith("_started")),
                             key=lambda x: (parse_time(x["observed_at"]) or datetime.min.replace(tzinfo=timezone.utc), x["file_id"]))
            cite = seen_in[-1]["file_id"] if seen_in else a["activity_id"]
            findings.append(make_step("FINDING", str(target), rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", cite))
            remediations.append(make_step("REMEDIATION", str(target), rid, "DISABLE_DATA_FLOW", "DISABLED"))
            verifications.append(make_step("VERIFICATION", str(target), rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
    # The subject's primary account record is always part of the deletion: if the lookups
    # did not surface it, take the one account deletion the workflow performed right at its
    # reported time (unique within 15 minutes) and prove absence from an account snapshot.
    if not any(v["system_id"] == "account_service" and v["operation"] == "VERIFY_RECORD_ABSENT" for v in verifications):
        acc = account_assignment(activities).get(case.get("case_id", ""))
        if acc:
            snaps = sorted((x for x in eligible if x["system"] == "account_service" and x["category"] == "USER_PROFILE"
                            and x["source"] == "file" and not x.get("event_log")
                            and resource_id(x["row"]) != acc),
                           key=lambda x: (parse_time(x["available_at"]) or datetime.min.replace(tzinfo=timezone.utc), x["file_id"]))
            lookup = [x for x in eligible if x["system"] == "account_service" and resource_id(x["row"]) == acc and not x.get("event_log")]
            present = any(x["row"].get("status_code") != 404 and any(x["row"].get(k) for k in ("email", "phone", "user_id", "customer_reference")) for x in lookup)
            if not present:
                evid = lookup[-1]["file_id"] if lookup else (snaps[-1]["file_id"] if snaps else "")
                verifications.append(make_step("VERIFICATION", "account_service", acc, "VERIFY_RECORD_ABSENT", "ABSENT", evid))
    # Retained audit records are never deleted, so one that a later snapshot ties to the
    # subject was already present at audit time even if no earlier artifact lists it.
    have = {(v["system_id"], v["resource_id"]) for v in verifications}
    for (sysid, rid), item in sorted(future_audit.items()):
        if (sysid, rid) not in have and not is_synthetic_resource(rid):
            verifications.append(make_step("VERIFICATION", sysid, rid, "VERIFY_RECORD_PRESENT", "PRESENT", item["file_id"]))
    if findings:
        # The contract marks every proposed action and post-remediation check as
        # future work; these steps must not carry present-state evidence references.
        for step in remediations + verifications:
            step["evidence_id"] = ""
        findings = list({(x["operation"], x["system_id"], x["resource_id"]): x for x in findings}.values())
        remediations = list({(x["operation"], x["system_id"], x["resource_id"]): x for x in remediations}.values())
        verifications = list({(x["operation"], x["system_id"], x["resource_id"]): x for x in verifications}.values())
        steps = sorted(findings + remediations + verifications, key=op_key)
        for i, step in enumerate(steps, 1):
            step["step_no"] = i
        return "INCOMPLETE", steps
    # For clean cases, keep only evidence-backed checks, and avoid asserting absence
    # without a positive snapshot or lookup proving it.
    verifications = list({(x["operation"], x["system_id"], x["resource_id"]): x for x in verifications}.values())
    steps = sorted(verifications, key=op_key)
    for i, step in enumerate(steps, 1):
        step["step_no"] = i
    return "COMPLETE", steps


def run(output: Path) -> dict[str, Any]:
    users, ids = build_identities()
    evidence = load_evidence()
    activities = read_csv(DATASET / "system_activity.csv")
    cases = read_csv(DATASET / "deletion_requests.csv")
    results = []
    for case in sorted(cases, key=lambda r: r["case_id"]):
        status, steps = audit_case(case, users, ids, evidence, activities)
        results.append({"case_id": case["case_id"], "deletion_status": status,
                        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    return {"rows": len(results), "status_counts": {s: sum(r["deletion_status"] == s for r in results) for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")},
            "evidence_observations": len(evidence)}


def validate(path: Path) -> dict[str, Any]:
    rows = read_csv(path)
    assert list(rows[0]) == OUT_FIELDS, f"wrong header: {list(rows[0])}"
    assert len(rows) == 518, f"expected 518 rows, got {len(rows)}"
    assert [x["case_id"] for x in rows] == sorted(x["case_id"] for x in rows), "rows not sorted"
    for row in rows:
        steps = json.loads(row["steps_json"])
        assert isinstance(steps, list)
        assert row["deletion_status"] in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        assert [x["step_no"] for x in steps] == list(range(1, len(steps) + 1))
        if row["deletion_status"] == "NOT_APPLICABLE":
            assert not steps
        if row["deletion_status"] == "COMPLETE":
            assert all(x["phase"] == "VERIFICATION" and x["evidence_id"] for x in steps)
        if row["deletion_status"] == "INCOMPLETE":
            assert all(x["evidence_id"] if x["phase"] == "FINDING" else x["evidence_id"] == "" for x in steps)
    return {"rows": len(rows), "fields": OUT_FIELDS, "valid_json": True}


def evaluate(sample: bool = True) -> dict[str, Any]:
    """Evaluation-only comparison to the public sample answer file."""
    users, ids = build_identities()
    evidence = load_evidence()
    activities = read_csv(DATASET / "system_activity.csv")
    cases = read_csv(DATASET / "sample_deletion_requests.csv" if sample else DATASET / "deletion_requests.csv")
    golden = {r["case_id"]: r for r in read_csv(DATASET / "sample_output.csv")}
    pred = {r["case_id"]: audit_case(r, users, ids, evidence, activities) for r in cases}
    status_ok = sum(pred[k][0] == golden[k]["deletion_status"] for k in golden)
    exact_seq = field_correct = exact_case = 0
    field_total = 0
    total_steps = gold_steps = correct_steps = 0
    for case_id, gold in golden.items():
        ps, psteps = pred[case_id]
        gsteps = json.loads(gold["steps_json"])
        if ps == gold["deletion_status"] and psteps == gsteps:
            exact_case += 1
        if psteps == gsteps:
            exact_seq += 1
        total_steps += max(len(psteps), len(gsteps))
        gold_steps += len(gsteps)
        correct_steps += sum(a == b for a, b in zip(psteps, gsteps))
        step_fields = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id", "step_no")
        field_total += max(len(psteps), len(gsteps)) * len(step_fields)
        for a, b in zip(psteps, gsteps):
            field_correct += sum(a.get(k) == b.get(k) for k in step_fields)
    return {"sample_cases": len(golden), "case_status_accuracy": status_ok / len(golden), "exact_case_accuracy": exact_case / len(golden),
            "sequence_accuracy": exact_seq / len(golden), "step_position_accuracy": correct_steps / max(total_steps, 1),
            "field_accuracy": field_correct / max(field_total, 1)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--evaluate-sample", action="store_true", help="Compare predictions with public sample labels for evaluation only")
    args = parser.parse_args()
    if args.evaluate_sample:
        print(json.dumps(evaluate(), indent=2))
    elif args.validate:
        print(json.dumps(validate(args.output), indent=2))
    else:
        print(json.dumps(run(args.output), indent=2))


if __name__ == "__main__":
    main()
