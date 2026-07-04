import json
import re
from hashlib import sha256
from pathlib import Path

REDACTION_MARKER = "<REDACTED>"
SECRET_KEYS = {"secret", "match", "line", "value", "password", "token", "apikey", "api_key", "privatekey", "private_key"}


class GitleaksParserError(ValueError):
    pass


def normalize_gitleaks_output(output: str | list | dict, scan_root: str | None = None) -> dict:
    records = _decode_records(output)
    accepted_records: list[dict] = []
    findings: list[dict] = []
    dropped_out_of_scope_count = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        finding = _normalize_finding(record, scan_root=scan_root)
        if not finding:
            dropped_out_of_scope_count += 1
            continue
        accepted_records.append(record)
        findings.append(finding)
    return {
        "scan_root": str(scan_root or ""),
        "finding_count": len(findings),
        "affected_files_count": len({finding.get("file_path") for finding in findings if finding.get("file_path")}),
        "dropped_out_of_scope_count": dropped_out_of_scope_count,
        "rule_summary": _count_values(finding.get("rule_id") for finding in findings),
        "provider_summary": _count_values(finding.get("provider") for finding in findings),
        "severity_summary": _count_values(finding.get("severity") for finding in findings),
        "findings": findings,
        "raw_json": redact_gitleaks_value(accepted_records),
        "limitations": [
            "Gitleaks detections are secret-exposure evidence only.",
            "Detected secrets were not validated or used.",
            "Secret values are redacted before storage, prompts, reports, and Telegram output.",
        ],
    }


def extract_gitleaks_vault_payloads(output: str | list | dict, scan_root: str | None = None) -> list[dict]:
    payloads: list[dict] = []
    for record in _decode_records(output):
        if not isinstance(record, dict):
            continue
        finding = _normalize_finding(record, scan_root=scan_root)
        if not finding:
            continue
        raw_value = str(_first(record, "Secret", "secret", "Match", "match") or "")
        if not raw_value:
            continue
        payloads.append(
            {
                "finding_reference": {
                    "rule_id": finding.get("rule_id"),
                    "file_path": finding.get("file_path"),
                    "line_number": finding.get("line_number"),
                    "fingerprint": finding.get("fingerprint"),
                    "secret_hash": finding.get("secret_hash"),
                },
                "secret_payload": {
                    "secret": raw_value,
                    "rule_id": finding.get("rule_id"),
                    "file_path": finding.get("file_path"),
                    "line_number": finding.get("line_number"),
                    "fingerprint": finding.get("fingerprint"),
                },
            }
        )
    return payloads


def summarize_gitleaks_evidence(evidence: dict) -> dict:
    findings = evidence.get("findings") or []
    return {
        "finding_count": int(evidence.get("finding_count") or len(findings)),
        "affected_files_count": int(evidence.get("affected_files_count") or len({finding.get("file_path") for finding in findings if finding.get("file_path")})),
        "rule_summary": evidence.get("rule_summary") or _count_values(finding.get("rule_id") for finding in findings),
        "provider_summary": evidence.get("provider_summary") or _count_values(finding.get("provider") for finding in findings),
        "severity_summary": evidence.get("severity_summary") or _count_values(finding.get("severity") for finding in findings),
    }


def redact_gitleaks_value(value: object) -> object:
    if isinstance(value, list):
        return [redact_gitleaks_value(item) for item in value]
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                redacted[key] = REDACTION_MARKER
            else:
                redacted[key] = redact_gitleaks_value(item)
        return redacted
    return value


def _decode_records(output: str | list | dict) -> list[dict]:
    if isinstance(output, list):
        return [item for item in output if isinstance(item, dict)]
    if isinstance(output, dict):
        for key in ("findings", "Findings", "results", "Results"):
            if isinstance(output.get(key), list):
                return [item for item in output[key] if isinstance(item, dict)]
        return [output]
    text = str(output or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GitleaksParserError("Unable to parse Gitleaks JSON output.") from exc
    return _decode_records(decoded)


def _normalize_finding(record: dict, scan_root: str | None = None) -> dict | None:
    rule_id = _first(record, "RuleID", "Rule", "rule_id", "rule")
    description = _first(record, "Description", "description")
    file_path = _safe_relative_path(_first(record, "File", "file", "Path", "path"), scan_root)
    if file_path is None:
        return None
    line = _first(record, "StartLine", "Line", "line", "start_line")
    entropy = _first(record, "Entropy", "entropy")
    fingerprint = _first(record, "Fingerprint", "fingerprint")
    tags = _as_list(_first(record, "Tags", "tags"))
    severity = _infer_severity(rule_id, tags, entropy)
    provider = _infer_provider(rule_id, tags, description)
    secret = str(_first(record, "Secret", "secret", "Match", "match") or "")
    return {
        "rule_id": str(rule_id or "unknown"),
        "type": str(description or rule_id or "secret"),
        "file_path": file_path,
        "line_number": _to_int(line),
        "entropy": _to_float(entropy),
        "severity": severity,
        "fingerprint": str(fingerprint or ""),
        "secret_hash": _stable_secret_hash(secret),
        "evidence_id": "",
        "provider": provider,
        "redacted_secret_preview": _redacted_preview(secret),
        "commit": _safe_text(_first(record, "Commit", "commit")),
        "author": _safe_text(_first(record, "Author", "author")),
        "email": _safe_text(_first(record, "Email", "email")),
        "date": _safe_text(_first(record, "Date", "date")),
        "tags": [str(tag) for tag in tags if str(tag).strip()][:10],
    }


def _first(record: dict, *keys: str) -> object:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_relative_path(value: object, scan_root: str | None) -> str | None:
    path_text = str(value or "").replace("\\", "/").strip()
    if not path_text:
        return ""
    if not scan_root:
        return path_text.lstrip("./")[:500]
    root = Path(scan_root).resolve()
    if not root.exists():
        return path_text.lstrip("./")[:500]
    try:
        path = Path(path_text)
        candidates = [path.resolve()] if path.is_absolute() else [(root / path).resolve(), (Path.cwd().resolve() / path).resolve()]
        for candidate in candidates:
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.exists() and candidate.is_file():
                return str(relative).replace("\\", "/")[:500]
        return None
    except (OSError, ValueError):
        return None


def _redacted_preview(secret: str) -> str:
    if not secret:
        return REDACTION_MARKER
    return f"{REDACTION_MARKER} len={len(secret)}"


def _stable_secret_hash(secret: str) -> str:
    if not secret:
        return ""
    return sha256(secret.encode("utf-8")).hexdigest()


def _infer_provider(rule_id: object, tags: list[object], description: object) -> str:
    text = " ".join([str(rule_id or ""), str(description or ""), " ".join(str(tag) for tag in tags)]).lower()
    providers = {
        "aws": "aws",
        "github": "github",
        "gitlab": "gitlab",
        "slack": "slack",
        "stripe": "stripe",
        "google": "google",
        "private": "private-key",
        "ssh": "ssh",
        "npm": "npm",
    }
    for needle, provider in providers.items():
        if needle in text:
            return provider
    return "unknown"


def _infer_severity(rule_id: object, tags: list[object], entropy: object) -> str:
    text = " ".join([str(rule_id or ""), " ".join(str(tag) for tag in tags)]).lower()
    if any(term in text for term in ("private-key", "aws", "github", "token", "secret", "password")):
        return "high"
    parsed_entropy = _to_float(entropy)
    if parsed_entropy is not None and parsed_entropy >= 4.5:
        return "medium"
    return "unknown"


def _safe_text(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:300]


def _to_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _count_values(values: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        cleaned = str(value or "unknown").strip() or "unknown"
        counts[cleaned] = counts.get(cleaned, 0) + 1
    return counts


def contains_unredacted_secret(value: object, secret: str) -> bool:
    if not secret:
        return False
    return bool(re.search(re.escape(secret), json.dumps(value, default=str)))
