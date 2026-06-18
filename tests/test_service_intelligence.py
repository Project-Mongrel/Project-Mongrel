from app.services.service_intelligence import get_service_intelligence


def test_known_service_lookup() -> None:
    intelligence = get_service_intelligence(service_name="ssh", port="22")

    assert intelligence["name"] == "SSH"
    assert "remote administration" in intelligence["description"]


def test_unknown_service_lookup() -> None:
    intelligence = get_service_intelligence(service_name="unknown-service", port="9999")

    assert intelligence["name"] == "unknown-service"
    assert intelligence["description"] == "Description unavailable."
    assert intelligence["recommendation"] == "Manual review recommended."


def test_recommendation_exists() -> None:
    intelligence = get_service_intelligence(service_name="mongodb", port="27017")

    assert intelligence["recommendation"]
    assert intelligence["recommendation"] != "Manual review recommended."
