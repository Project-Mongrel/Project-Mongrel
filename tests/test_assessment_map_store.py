import multiprocessing
import sqlite3
import threading
import time
from pathlib import Path
from dataclasses import replace

import pytest

from app.services import assessment_map_store
from app.services.assessment_map_identity import CanonicalIdentity, canonical_endpoint, canonical_hostname
from app.services.assessment_map_store import (
    AssessmentMapIdentityCollisionError,
    AssessmentMapScopeError,
    attach_evidence,
    create_or_update_validation_attempt,
    get_ingestion_ledger,
    get_or_create_assertion,
    get_or_create_entity,
    initialize_assessment_map_schema,
    list_assertions,
    list_entities,
    write_ingestion_ledger,
)
from app.services.assessment_store import create_assessment, record_assessment_scan
from app.services.findings_store import (
    _get_connection,
    add_finding,
    close_findings_database,
    configure_findings_database,
)
from app.services.metasploit_approval import propose_metasploit_action
from app.services.sqlite_runtime import SQLITE_BUSY_TIMEOUT_MS, configure_operational_connection


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    database_path = tmp_path / "mongrel.db"
    configure_findings_database(database_path)
    yield database_path
    close_findings_database()
    configure_findings_database(None)


def _entity(user_id: int, assessment_id: int, hostname: str = "example.com") -> dict:
    return get_or_create_entity(
        user_id=user_id,
        assessment_id=assessment_id,
        identity=canonical_hostname(hostname),
        display_value=hostname,
    )


def _proposal(user_id: int, assessment_id: int):
    return propose_metasploit_action(
        user_id,
        {"module": "auxiliary/scanner/http/http_version", "action_type": "auxiliary_validation"},
        assessment_context={"assessment_id": assessment_id},
    )


def _initialize_schema_in_process(database_path: str, start_event, result_queue) -> None:
    try:
        configure_findings_database(Path(database_path))
        start_event.wait(timeout=3)
        initialize_assessment_map_schema()
        result_queue.put(None)
    except BaseException as exc:
        result_queue.put(type(exc).__name__)
    finally:
        close_findings_database()


def test_initialization_and_entity_insertion_are_idempotent() -> None:
    assessment = create_assessment("Map", user_id=100)
    initialize_assessment_map_schema()
    initialize_assessment_map_schema()
    first = _entity(100, assessment["id"])
    second = _entity(100, assessment["id"])
    assert first["id"] == second["id"]
    assert len(list_entities(user_id=100, assessment_id=assessment["id"])) == 1


def test_concurrent_initialization_is_idempotent_and_thread_safe() -> None:
    create_assessment("Concurrent schema", user_id=112)
    barrier = threading.Barrier(4)
    errors: list[BaseException] = []

    def initialize() -> None:
        try:
            barrier.wait(timeout=2)
            initialize_assessment_map_schema()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=initialize) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    tables = {
        row["name"]
        for row in _get_connection().execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'assessment_map_%'"
        ).fetchall()
    }
    assert tables == {
        "assessment_map_entities",
        "assessment_map_assertions",
        "assessment_map_evidence_links",
        "assessment_map_ingestions",
    }


def test_concurrent_initialization_is_safe_across_processes(isolated_database) -> None:
    create_assessment("Concurrent process schema", user_id=122)
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_initialize_schema_in_process,
            args=(str(isolated_database), start_event, result_queue),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=8)
    try:
        assert all(not process.is_alive() for process in processes)
        assert [result_queue.get(timeout=1) for _ in processes] == [None, None]
        initialize_assessment_map_schema()
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        result_queue.close()


def test_hash_collision_is_rejected_when_canonical_key_differs() -> None:
    assessment = create_assessment("Collision", user_id=101)
    original = canonical_hostname("example.com")
    _entity(101, assessment["id"])
    collision = CanonicalIdentity(
        entity_type="hostname",
        version=original.version,
        canonical_key=original.canonical_key + "-different",
        identity_hash=original.identity_hash,
        payload={"hostname": "different.example"},
    )
    with pytest.raises(AssessmentMapIdentityCollisionError):
        get_or_create_entity(user_id=101, assessment_id=assessment["id"], identity=collision)


def test_forged_canonical_identity_version_key_and_hash_are_rejected() -> None:
    assessment = create_assessment("Canonical integrity", user_id=113)
    original = canonical_hostname("example.com")
    for forged in (
        replace(original, version="assessment-map.identity.v0"),
        replace(original, canonical_key=original.canonical_key + "-changed"),
        replace(original, identity_hash="0" * 64),
    ):
        with pytest.raises((ValueError, AssessmentMapIdentityCollisionError)):
            get_or_create_entity(user_id=113, assessment_id=assessment["id"], identity=forged)


def test_cross_user_cross_assessment_and_ownerless_scopes_are_rejected() -> None:
    first = create_assessment("First", user_id=102)
    second = create_assessment("Second", user_id=103)
    ownerless = create_assessment("Legacy")
    entity = _entity(102, first["id"])

    with pytest.raises(AssessmentMapScopeError):
        list_entities(user_id=103, assessment_id=first["id"])
    with pytest.raises(AssessmentMapScopeError):
        get_or_create_assertion(
            user_id=103,
            assessment_id=second["id"],
            subject_entity_id=entity["id"],
            predicate="has_value",
            value=1,
        )
    with pytest.raises(AssessmentMapScopeError):
        get_or_create_entity(
            user_id=0, assessment_id=ownerless["id"], identity=canonical_hostname("legacy.example")
        )


def test_assertion_null_and_zero_values_are_distinct_and_idempotent() -> None:
    assessment = create_assessment("Assertions", user_id=104)
    entity = _entity(104, assessment["id"])
    null = get_or_create_assertion(
        user_id=104, assessment_id=assessment["id"], subject_entity_id=entity["id"],
        predicate="observed_count", value=None,
    )
    zero = get_or_create_assertion(
        user_id=104, assessment_id=assessment["id"], subject_entity_id=entity["id"],
        predicate="observed_count", value=0,
    )
    repeated = get_or_create_assertion(
        user_id=104, assessment_id=assessment["id"], subject_entity_id=entity["id"],
        predicate="observed_count", value=0,
    )
    assert null["id"] != zero["id"]
    assert repeated["id"] == zero["id"]


def test_assertion_hash_collision_is_rejected_using_canonical_content(monkeypatch) -> None:
    assessment = create_assessment("Assertion collision", user_id=120)
    entity = _entity(120, assessment["id"])

    class FixedDigest:
        def hexdigest(self) -> str:
            return "a" * 64

    monkeypatch.setattr(assessment_map_store.hashlib, "sha256", lambda value: FixedDigest())
    get_or_create_assertion(
        user_id=120, assessment_id=assessment["id"], subject_entity_id=entity["id"],
        predicate="observed_count", value=1,
    )
    with pytest.raises(AssessmentMapIdentityCollisionError, match="assertion hash collision"):
        get_or_create_assertion(
            user_id=120, assessment_id=assessment["id"], subject_entity_id=entity["id"],
            predicate="observed_count", value=2,
        )


def test_same_evidence_occurrence_can_support_entity_and_assertion_separately() -> None:
    assessment = create_assessment("Evidence", user_id=105)
    finding = add_finding(105, {"source": "nmap", "target": "example.com"})
    scan = record_assessment_scan(
        assessment["id"], tool="nmap", status="completed", finding_id=finding["id"]
    )
    entity = _entity(105, assessment["id"])
    assertion = get_or_create_assertion(
        user_id=105, assessment_id=assessment["id"], subject_entity_id=entity["id"],
        predicate="is_reachable", value=True,
    )
    entity_link = attach_evidence(
        user_id=105, assessment_id=assessment["id"], entity_id=entity["id"], scan_id=scan["id"],
        finding_id=finding["id"], source_tool="nmap", evidence_kind="normalized_finding",
        evidence_fingerprint="occurrence-1",
    )
    assertion_link = attach_evidence(
        user_id=105, assessment_id=assessment["id"], assertion_id=assertion["id"], scan_id=scan["id"],
        finding_id=finding["id"], source_tool="nmap", evidence_kind="normalized_finding",
        evidence_fingerprint="occurrence-1",
    )
    repeated = attach_evidence(
        user_id=105, assessment_id=assessment["id"], entity_id=entity["id"], scan_id=scan["id"],
        finding_id=finding["id"], source_tool="nmap", evidence_kind="normalized_finding",
        evidence_fingerprint="occurrence-1",
    )
    assert entity_link["id"] != assertion_link["id"]
    assert repeated["id"] == entity_link["id"]


def test_evidence_fingerprint_replay_rejects_changed_provenance() -> None:
    assessment = create_assessment("Evidence collision", user_id=114)
    scan = record_assessment_scan(assessment["id"], tool="nmap", status="completed")
    entity = _entity(114, assessment["id"])
    original = attach_evidence(
        user_id=114, assessment_id=assessment["id"], entity_id=entity["id"], scan_id=scan["id"],
        source_tool="nmap", evidence_kind="service", evidence_path="ports[0]",
        evidence_fingerprint="same-occurrence",
    )
    replay = attach_evidence(
        user_id=114, assessment_id=assessment["id"], entity_id=entity["id"], scan_id=scan["id"],
        source_tool="nmap", evidence_kind="service", evidence_path="ports[0]",
        evidence_fingerprint="same-occurrence",
    )
    assert replay["id"] == original["id"]
    with pytest.raises(AssessmentMapIdentityCollisionError, match="changed provenance"):
        attach_evidence(
            user_id=114, assessment_id=assessment["id"], entity_id=entity["id"], scan_id=scan["id"],
            source_tool="nmap", evidence_kind="different", evidence_path="ports[0]",
            evidence_fingerprint="same-occurrence",
        )


def test_separately_approved_validation_attempts_are_not_merged_by_fingerprint() -> None:
    assessment = create_assessment("Validation", user_id=106)
    first = create_or_update_validation_attempt(
        user_id=106, assessment_id=assessment["id"], attempt_key="proposal-one", tool="metasploit",
        request_fingerprint="same-request", approval_status="approved", execution_status="not_started",
    )
    second = create_or_update_validation_attempt(
        user_id=106, assessment_id=assessment["id"], attempt_key="proposal-two", tool="metasploit",
        request_fingerprint="same-request", approval_status="approved", execution_status="not_started",
    )
    updated = create_or_update_validation_attempt(
        user_id=106, assessment_id=assessment["id"], attempt_key="proposal-one", tool="metasploit",
        request_fingerprint="same-request", approval_status="approved", execution_status="completed",
        validation_state="DETECTED", session_established=False,
    )
    assert first["id"] != second["id"]
    assert updated["id"] == first["id"]
    assert updated["validation_state"] == "DETECTED"


def test_validation_proposal_must_match_exact_owner_and_assessment() -> None:
    first = create_assessment("Proposal first", user_id=115)
    second = create_assessment("Proposal second", user_id=115)
    proposal = _proposal(115, first["id"])
    with pytest.raises(AssessmentMapScopeError):
        create_or_update_validation_attempt(
            user_id=115, assessment_id=second["id"], attempt_key="cross-scope", tool="metasploit",
            proposal_id=proposal.id, request_fingerprint=proposal.fingerprint,
            approval_status="approved", execution_status="not_started",
        )


def test_validation_attempt_rejects_immutable_identity_changes() -> None:
    assessment = create_assessment("Validation identity", user_id=116)
    first_proposal = _proposal(116, assessment["id"])
    second_proposal = _proposal(116, assessment["id"])
    first_entity = _entity(116, assessment["id"], "one.example")
    second_entity = _entity(116, assessment["id"], "two.example")
    common = dict(
        user_id=116, assessment_id=assessment["id"], attempt_key="attempt-one", tool="metasploit",
        proposal_id=first_proposal.id, request_fingerprint="request-one", target_entity_id=first_entity["id"],
        module="auxiliary/scanner/http/http_version", action_type="auxiliary_validation",
        approval_status="approved", execution_status="not_started",
    )
    create_or_update_validation_attempt(**common)
    for changed in (
        {"proposal_id": second_proposal.id},
        {"module": "auxiliary/scanner/http/title"},
        {"target_entity_id": second_entity["id"]},
    ):
        with pytest.raises(AssessmentMapIdentityCollisionError, match="immutable identity"):
            create_or_update_validation_attempt(**(common | changed))


def test_terminal_validation_attempt_cannot_regress() -> None:
    assessment = create_assessment("Validation terminal", user_id=117)
    common = dict(
        user_id=117, assessment_id=assessment["id"], attempt_key="terminal", tool="metasploit",
        request_fingerprint="terminal-request", approval_status="approved",
    )
    create_or_update_validation_attempt(
        **common, execution_status="completed", validation_state="DETECTED"
    )
    with pytest.raises(AssessmentMapIdentityCollisionError, match="cannot regress"):
        create_or_update_validation_attempt(
            **common, execution_status="executing", validation_state=None
        )


def test_ingestion_ledger_is_versioned_digest_scoped_and_idempotent() -> None:
    assessment = create_assessment("Ledger", user_id=107)
    scan = record_assessment_scan(assessment["id"], tool="nmap", status="completed")
    first = write_ingestion_ledger(
        user_id=107, assessment_id=assessment["id"], scan_id=scan["id"], ingestion_version=1,
        source_digest="sha256:first", status="complete", entity_count=2,
    )
    repeated = write_ingestion_ledger(
        user_id=107, assessment_id=assessment["id"], scan_id=scan["id"], ingestion_version=1,
        source_digest="sha256:first", status="complete", entity_count=2,
    )
    changed = write_ingestion_ledger(
        user_id=107, assessment_id=assessment["id"], scan_id=scan["id"], ingestion_version=1,
        source_digest="sha256:changed", status="complete", entity_count=3,
    )
    assert first == repeated
    assert changed["source_digest"] != first["source_digest"]
    assert get_ingestion_ledger(
        user_id=107, assessment_id=assessment["id"], scan_id=scan["id"], ingestion_version=1,
        source_digest="sha256:first",
    ) is not None


def test_database_foreign_keys_reject_cross_scope_raw_insert() -> None:
    first = create_assessment("FK first", user_id=108)
    second = create_assessment("FK second", user_id=109)
    entity = _entity(108, first["id"])
    connection = _get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        with connection:
            connection.execute(
                """
                INSERT INTO assessment_map_assertions (
                    assessment_id, user_id, subject_entity_id, predicate, normalized_value_json,
                    polarity, assertion_hash, canonical_key, attributes_json,
                    first_seen_at, last_seen_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'invalid_cross_scope', 'true', 'observed', 'hash', 'key', '{}',
                          'now', 'now', 'now', 'now')
                """,
                (second["id"], 109, entity["id"]),
            )


def test_database_trigger_rejects_same_user_cross_assessment_finding_evidence() -> None:
    first = create_assessment("Finding first", user_id=118)
    second = create_assessment("Finding second", user_id=118)
    finding = add_finding(118, {"source": "nuclei", "target": "first.example"})
    record_assessment_scan(first["id"], tool="nuclei", status="completed", finding_id=finding["id"])
    entity = _entity(118, second["id"], "second.example")
    connection = _get_connection()
    with pytest.raises(sqlite3.IntegrityError, match="finding scope violation"):
        with connection:
            connection.execute(
                """INSERT INTO assessment_map_evidence_links (
                       assessment_id, user_id, destination_type, destination_id, entity_id,
                       finding_id, source_tool, evidence_kind, evidence_fingerprint,
                       metadata_json, created_at
                   ) VALUES (?, ?, 'entity', ?, ?, ?, 'nuclei', 'template_match', 'cross-scope', '{}', 'now')""",
                (second["id"], 118, entity["id"], entity["id"], finding["id"]),
            )


def test_database_trigger_rejects_same_user_cross_assessment_proposal() -> None:
    first = create_assessment("Raw proposal first", user_id=119)
    second = create_assessment("Raw proposal second", user_id=119)
    proposal = _proposal(119, first["id"])
    initialize_assessment_map_schema()
    connection = _get_connection()
    with pytest.raises(sqlite3.IntegrityError, match="proposal scope violation"):
        with connection:
            connection.execute(
                """INSERT INTO assessment_validation_attempts (
                       assessment_id, user_id, attempt_key, tool, proposal_id, request_fingerprint,
                       approval_status, execution_status, limitations_json, created_at, updated_at
                   ) VALUES (?, ?, 'raw-cross-scope', 'metasploit', ?, ?,
                             'approved', 'not_started', '[]', 'now', 'now')""",
                (second["id"], 119, proposal.id, proposal.fingerprint),
            )


def test_bounded_lookups_do_not_cross_scope() -> None:
    assessment = create_assessment("Bounded", user_id=110)
    first = _entity(110, assessment["id"], "one.example")
    _entity(110, assessment["id"], "two.example")
    get_or_create_assertion(
        user_id=110, assessment_id=assessment["id"], subject_entity_id=first["id"],
        predicate="observed_count", value=0,
    )
    assert len(list_entities(user_id=110, assessment_id=assessment["id"], limit=1)) == 1
    assert len(list_assertions(user_id=110, assessment_id=assessment["id"], entity_id=first["id"], limit=1)) == 1


def test_store_recovers_when_sqlite_lock_releases_within_shared_retry_window(isolated_database) -> None:
    assessment = create_assessment("Contention", user_id=111)
    initialize_assessment_map_schema()
    locker = sqlite3.connect(
        isolated_database, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000, check_same_thread=False
    )
    configure_operational_connection(locker, enable_wal=True)
    locker.execute("BEGIN IMMEDIATE")
    locker.execute("UPDATE assessments SET updated_at = updated_at WHERE id = ?", (assessment["id"],))

    def release() -> None:
        time.sleep(0.6)
        locker.commit()

    thread = threading.Thread(target=release)
    thread.start()
    try:
        entity = get_or_create_entity(
            user_id=111,
            assessment_id=assessment["id"],
            identity=canonical_endpoint("https://example.com/"),
        )
        assert entity["entity_type"] == "endpoint"
    finally:
        thread.join(timeout=2)
        if thread.is_alive():
            locker.rollback()
        locker.close()
    assert not thread.is_alive()


def test_schema_initialization_recovers_after_transaction_failure(monkeypatch) -> None:
    create_assessment("Schema recovery", user_id=121)
    original = assessment_map_store._create_schema
    calls = 0

    def fail_once(connection) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            connection.execute("CREATE TABLE assessment_map_transient_failure (id INTEGER PRIMARY KEY)")
            raise RuntimeError("synthetic schema failure")
        original(connection)

    monkeypatch.setattr(assessment_map_store, "_create_schema", fail_once)
    with pytest.raises(RuntimeError, match="synthetic schema failure"):
        initialize_assessment_map_schema()
    initialize_assessment_map_schema()
    tables = {
        row["name"]
        for row in _get_connection().execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'assessment_map_%'"
        ).fetchall()
    }
    assert "assessment_map_transient_failure" not in tables
    assert "assessment_map_entities" in tables
