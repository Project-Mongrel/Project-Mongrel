from app.services.assessment_store import (
    get_assessment,
    list_assessment_artifacts,
    list_assessment_notes,
    list_assessment_scans,
    list_assessment_targets,
)
from app.services.findings_store import get_user_finding


def build_assessment_context(assessment_id: int, user_id: int) -> dict:
    assessment = get_assessment(assessment_id)
    if assessment is None:
        raise ValueError("Assessment not found.")

    scans = list_assessment_scans(assessment_id)
    enriched_scans = [_enrich_scan(scan, user_id) for scan in scans]
    return {
        "assessment": assessment,
        "targets": list_assessment_targets(assessment_id),
        "scans": enriched_scans,
        "findings": [scan["finding"] for scan in enriched_scans if scan.get("finding")],
        "artifacts": list_assessment_artifacts(assessment_id),
        "notes": list_assessment_notes(assessment_id),
    }


def _enrich_scan(scan: dict, user_id: int) -> dict:
    finding_id = scan.get("finding_id")
    finding = get_user_finding(user_id=user_id, finding_id=str(finding_id)) if finding_id else None
    return {**scan, "finding": finding}
