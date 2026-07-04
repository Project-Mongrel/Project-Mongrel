import sqlite3

import pytest
from cryptography.fernet import Fernet

from app.services.evidence_vault import (
    EvidenceVaultDecryptError,
    EvidenceVaultUnavailable,
    close_evidence_vault,
    configure_evidence_vault,
    reveal_secret_evidence,
    store_secret_evidence,
)


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path):
    configure_evidence_vault(tmp_path / "vault.db", Fernet.generate_key().decode("utf-8"))
    yield
    close_evidence_vault()
    configure_evidence_vault(None, None)


def test_evidence_vault_encrypts_and_recovers_exact_value(tmp_path) -> None:
    raw_value = "".join(("gh", "p_", "runtimeOnly", "000000000000000000000000"))
    record = store_secret_evidence(
        assessment_id="42",
        finding_reference={"rule_id": "github-pat", "file_path": "fake_secrets.env"},
        secret_payload={"secret": raw_value},
    )

    assert record["evidence_id"]
    assert record["assessment_id"] == "42"
    assert raw_value not in record["encrypted_secret_payload"]

    revealed = reveal_secret_evidence(record["evidence_id"], reveal_metadata={"actor": "test"})
    assert revealed["secret_payload"]["secret"] == raw_value
    assert revealed["reveal_audit"][0]["metadata"]["actor"] == "test"


def test_evidence_vault_ciphertext_does_not_contain_plaintext(tmp_path) -> None:
    raw_value = "".join(("AK", "IA", "IOSFODNN7", "EXAMPLE"))
    record = store_secret_evidence(
        assessment_id=None,
        finding_reference={"rule_id": "aws-access-token"},
        secret_payload={"secret": raw_value},
    )
    connection = sqlite3.connect(tmp_path / "vault.db")
    try:
        ciphertext = connection.execute("SELECT encrypted_secret_payload FROM secret_evidence_vault").fetchone()[0]
    finally:
        connection.close()

    assert ciphertext == record["encrypted_secret_payload"]
    assert raw_value not in ciphertext


def test_evidence_vault_wrong_key_fails(tmp_path) -> None:
    raw_value = "".join(("xoxb-", "000000000000-", "000000000000-", "runtimeOnly"))
    first_key = Fernet.generate_key().decode("utf-8")
    second_key = Fernet.generate_key().decode("utf-8")
    configure_evidence_vault(tmp_path / "vault.db", first_key)
    record = store_secret_evidence(
        assessment_id=None,
        finding_reference={"rule_id": "slack-token"},
        secret_payload={"secret": raw_value},
    )

    configure_evidence_vault(tmp_path / "vault.db", second_key)

    with pytest.raises(EvidenceVaultDecryptError):
        reveal_secret_evidence(record["evidence_id"])


def test_evidence_vault_missing_key_fails_closed(tmp_path) -> None:
    configure_evidence_vault(tmp_path / "vault.db", None)

    with pytest.raises(EvidenceVaultUnavailable):
        store_secret_evidence(
            assessment_id=None,
            finding_reference={"rule_id": "github-pat"},
            secret_payload={"secret": "redacted-by-test"},
        )
