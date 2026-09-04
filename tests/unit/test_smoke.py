from importlib.metadata import version


def test_package_version() -> None:
    assert version("cloudshield") == "0.1.0"
