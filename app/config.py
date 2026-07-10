from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "app.db"
SCANS_DIR = DATA_DIR / "scans"

TOOL_TIMEOUT_SECONDS = 15 * 60
VALIDATE_CONCURRENCY = 5


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    SCANS_DIR.mkdir(exist_ok=True)
