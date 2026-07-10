from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "Secure Code Review" in r.text


def test_static_js_served():
    r = client.get("/static/app.js")
    assert r.status_code == 200
