import pytest

from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.observation_store import (
    add_observation,
    add_observations,
    clear_user_observations,
    get_investigation_observations,
    get_observations_by_type,
    get_user_observations,
)


@pytest.fixture(autouse=True)
def sqlite_observation_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_add_single_observation() -> None:
    observation = add_observation(
        user_id=8001,
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    assert observation["id"]
    assert observation["source"] == "bbot"
    assert observation["observation_type"] == "subdomain"
    assert observation["value"] == "app.example.com"
    assert observation["target_key"] == "example.com"


def test_add_multiple_observations() -> None:
    observations = add_observations(
        [
            {
                "user_id": 8002,
                "source": "bbot",
                "observation_type": "subdomain",
                "value": "one.example.com",
                "target": "example.com",
            },
            {
                "user_id": 8002,
                "source": "bbot",
                "observation_type": "url",
                "value": "https://one.example.com",
                "target": "example.com",
            },
        ]
    )

    assert len(observations) == 2
    assert [observation["value"] for observation in get_user_observations(8002)] == [
        "one.example.com",
        "https://one.example.com",
    ]


def test_get_investigation_observations() -> None:
    add_observation(
        user_id=8003,
        investigation_id="investigation-1",
        source="bbot",
        observation_type="subdomain",
        value="one.example.com",
    )
    add_observation(
        user_id=8003,
        investigation_id="investigation-2",
        source="bbot",
        observation_type="subdomain",
        value="two.example.com",
    )

    observations = get_investigation_observations("investigation-1", 8003)

    assert len(observations) == 1
    assert observations[0]["value"] == "one.example.com"


def test_get_observations_by_type() -> None:
    add_observation(user_id=8004, source="bbot", observation_type="subdomain", value="one.example.com")
    add_observation(user_id=8004, source="bbot", observation_type="url", value="https://one.example.com")

    observations = get_observations_by_type(8004, "url")

    assert len(observations) == 1
    assert observations[0]["value"] == "https://one.example.com"


def test_user_isolation() -> None:
    observation = add_observation(user_id=8005, source="bbot", observation_type="subdomain", value="mine.example.com")
    add_observation(user_id=9999, source="bbot", observation_type="subdomain", value="theirs.example.com")

    assert get_user_observations(8005) == [observation]


def test_metadata_json_persistence() -> None:
    add_observation(
        user_id=8006,
        source="bbot",
        observation_type="technology",
        value="nginx",
        metadata={"module": "httpx", "confidence": 90},
    )

    observation = get_user_observations(8006)[0]

    assert observation["metadata"] == {"module": "httpx", "confidence": 90}


def test_observations_survive_connection_reload() -> None:
    observation = add_observation(
        user_id=8007,
        source="bbot",
        observation_type="email",
        value="security@example.com",
        metadata={"raw": "security@example.com"},
    )

    close_findings_database()

    assert get_user_observations(8007) == [observation]


def test_clear_user_observations() -> None:
    add_observation(user_id=8008, source="bbot", observation_type="subdomain", value="one.example.com")

    clear_user_observations(8008)

    assert get_user_observations(8008) == []
