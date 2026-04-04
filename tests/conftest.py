"""
tests/conftest.py

Shared pytest fixtures for the PIP test suite.
"""
import pytest
from pathlib import Path
from pip.models.context import ScanConfig, ScanMode, StealthProfile


@pytest.fixture
def default_config(tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        mode=ScanMode.QUICK,
        stealth=StealthProfile.NORMAL,
        output_dir=tmp_path,
        no_disk=True,
        timeout=30,
    )

@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path
