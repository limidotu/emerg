import pytest

from emergent_kali.models import LAB, RunConfig
from emergent_kali.store import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path)
    yield value
    value.close()


@pytest.fixture
def config():
    return RunConfig(authorization="I am authorized to test this local lab.", allowlist=[LAB], mock=True)
