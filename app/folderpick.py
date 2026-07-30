"""Native folder picker for the local machine.

Browsers deliberately never expose the absolute filesystem path of a folder
chosen in a web page, but the scanners need one. This app is local
single-user by design (server and browser run on the same machine), so the
backend opens the native directory dialog itself and returns the chosen
path. The dialog runs in a subprocess so tkinter never shares state or
threads with the server process.
"""
import subprocess
import sys
import threading

_DIALOG_SCRIPT = (
    "import tkinter as tk\n"
    "from tkinter import filedialog\n"
    "root = tk.Tk()\n"
    "root.withdraw()\n"
    "root.attributes('-topmost', True)\n"
    "root.update()\n"
    "print(filedialog.askdirectory("
    "title='Select the project folder to scan', parent=root))\n"
)

_LOCK = threading.Lock()


class PickerBusyError(RuntimeError):
    pass


def pick_folder(timeout: int = 600) -> str:
    """Open the native dialog; return the absolute path, or '' on cancel."""
    if not _LOCK.acquire(blocking=False):
        raise PickerBusyError("A folder picker is already open.")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _DIALOG_SCRIPT],
            capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "dialog failed to open")
        return (proc.stdout or "").strip()
    finally:
        _LOCK.release()
