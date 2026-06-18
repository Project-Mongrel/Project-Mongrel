from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_version_endpoint() -> None:
    response = client.get("/api/v1/version")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "Project Mongrel"
    assert payload["version"] == "0.1.0"
    assert payload["environment"] == "development"
