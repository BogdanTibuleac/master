"""Tests for repository/service/route backend boundaries."""

from pathlib import Path

from fastapi.testclient import TestClient

from malware_robustness.api.app import create_app
from malware_robustness.api.dependencies import get_dataset_service
from malware_robustness.domain import DatasetState, VectorizationSample
from malware_robustness.services import DatasetService


class FakeDatasetRepository:
    """Small in-memory repository used to test service and HTTP wiring."""

    def __init__(self, ready: bool = True) -> None:
        self.state = DatasetState(
            name="EMBER2018",
            raw_directory=Path("test-data"),
            archive_available=ready,
            manifest_available=ready,
            extracted_files_available=ready,
        )

    def get_state(self) -> DatasetState:
        return self.state

    def acquire(self) -> DatasetState:
        return self.state

    def verify(self) -> DatasetState:
        return self.state

    def vectorization_sample(self) -> VectorizationSample:
        return VectorizationSample(feature_count=2381, label=1, finite=True)


def test_dataset_service_rejects_smoke_test_when_data_is_not_ready() -> None:
    service = DatasetService(FakeDatasetRepository(ready=False))

    try:
        service.smoke_test()
    except RuntimeError as error:
        assert str(error) == "EMBER2018 dataset is not ready"
    else:
        raise AssertionError("Expected an unavailable dataset to be rejected")


def test_routes_expose_health_status_and_smoke_test() -> None:
    application = create_app()
    application.dependency_overrides[get_dataset_service] = lambda: DatasetService(
        FakeDatasetRepository()
    )
    client = TestClient(application)

    assert client.get("/health").json() == {"status": "ok"}
    cors_response = client.options(
        "/api/v1/datasets/ember2018/status",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert cors_response.headers["access-control-allow-origin"] == "http://localhost:3000"
    status_response = client.get("/api/v1/datasets/ember2018/status")
    assert status_response.status_code == 200
    assert status_response.json()["ready"] is True
    smoke_response = client.post("/api/v1/datasets/ember2018/smoke-test")
    assert smoke_response.status_code == 200
    assert smoke_response.json() == {"feature_count": 2381, "label": 1, "finite": True}
