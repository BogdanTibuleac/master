import json
from pathlib import Path

from malware_robustness.preprocessing import _read_locations, _sample_locations


def test_sample_locations_is_balanced_and_deterministic(tmp_path: Path) -> None:
    records = [
        {"label": label, "sha256": f"sample-{label}-{index}"}
        for label in (0, 1)
        for index in range(12)
    ]
    raw_path = tmp_path / "train_features_0.jsonl"
    raw_path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records), encoding="utf-8"
    )

    first = _sample_locations(tmp_path, "train", 4, 42)
    second = _sample_locations(tmp_path, "train", 4, 42)

    assert first == second
    assert len(first[0]) == len(first[1]) == 4
    selected = list(_read_locations([*first[0], *first[1]]))
    assert {record["label"] for record in selected} == {0, 1}
