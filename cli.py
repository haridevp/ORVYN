#!/usr/bin/env python3
"""Root executable wrapper for the AI Penetration Testing CLI.

Automatically runs with the backend virtual environment so all dependencies
(rich, requests, pydantic, etc.) are available out of the box.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "src" / "backend"

# Auto-detect best virtualenv python
venv_candidates = [
    ROOT / "src" / "backend" / ".venv" / "bin" / "python",
    ROOT / ".venv" / "bin" / "python",
    ROOT / ".venv-backend" / "bin" / "python",
]

python_bin = sys.executable
for candidate in venv_candidates:
    if candidate.is_file() and os.access(candidate, os.X_OK):
        python_bin = str(candidate)
        break

os.environ["PYTHONPATH"] = str(BACKEND_DIR) + ":" + os.environ.get("PYTHONPATH", "")
os.chdir(str(BACKEND_DIR))
os.execv(python_bin, [python_bin, str(BACKEND_DIR / "cli.py")] + sys.argv[1:])
