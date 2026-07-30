from fastapi.testclient import TestClient

from app import folderpick, main

client = TestClient(main.app)


def test_pick_folder_returns_path(monkeypatch):
    monkeypatch.setattr(main.folderpick, "pick_folder", lambda: "C:/repos/demo")
    r = client.post("/api/pick-folder")
    assert r.status_code == 200
    assert r.json() == {"path": "C:/repos/demo"}


def test_pick_folder_cancel_returns_empty(monkeypatch):
    monkeypatch.setattr(main.folderpick, "pick_folder", lambda: "")
    assert client.post("/api/pick-folder").json() == {"path": ""}


def test_pick_folder_busy_is_409(monkeypatch):
    def busy():
        raise folderpick.PickerBusyError("A folder picker is already open.")
    monkeypatch.setattr(main.folderpick, "pick_folder", busy)
    assert client.post("/api/pick-folder").status_code == 409


def test_pick_folder_disabled_in_docker(monkeypatch):
    monkeypatch.setenv("RUNNING_IN_DOCKER", "1")
    r = client.post("/api/pick-folder")
    assert r.status_code == 501
    assert "/projects" in r.json()["detail"]


def test_pick_folder_failure_is_500(monkeypatch):
    def boom():
        raise RuntimeError("no display")
    monkeypatch.setattr(main.folderpick, "pick_folder", boom)
    r = client.post("/api/pick-folder")
    assert r.status_code == 500
    assert "unavailable" in r.json()["detail"]


def test_picker_lock_prevents_concurrent_dialogs():
    # Hold the lock as if a dialog were open; a second call must refuse.
    assert folderpick._LOCK.acquire(blocking=False)
    try:
        try:
            folderpick.pick_folder()
            raised = False
        except folderpick.PickerBusyError:
            raised = True
        assert raised
    finally:
        folderpick._LOCK.release()
