import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Use a throw-away database so tests never touch real scan history.
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"

import pytest  # noqa: E402


@pytest.fixture(scope="session")
def predictor():
    from ai.url_detection.predictor import URLPredictor

    p = URLPredictor()
    assert p.model is not None, "Run `python scripts/train_models.py` before the tests"
    return p


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from backend.database.database import Base, engine
    from backend.main import app

    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:  # lifespan creates the tables
        yield c
