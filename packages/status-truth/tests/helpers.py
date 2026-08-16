from status_truth.contract import Provenance

NOW = "2026-01-01T00:00:00Z"


def provenance(value: object = True) -> Provenance:
    return Provenance.from_evidence(
        source="synthetic-test", observed_at=NOW, collector="unit-test", evidence=value,
    )

