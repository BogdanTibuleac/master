from malware_robustness.preprocessing import _balanced_records


def test_balanced_records_handles_class_ordered_input() -> None:
    records = iter(
        [{"label": 0, "id": index} for index in range(10)]
        + [{"label": -1, "id": 99}]
        + [{"label": 1, "id": index} for index in range(10)]
    )

    selected = list(_balanced_records(records, 6))

    assert [record["label"] for record in selected] == [0, 0, 0, 1, 1, 1]
