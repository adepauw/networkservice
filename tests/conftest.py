"""Test bootstrap. app.config reads the environment at import time, so give the
metadata store a writable SQLite path *before* any test imports app.main — a
bare ``pytest`` then works. A fresh temp dir per run: alerts persist to SQLite
now, so reusing one db file would leak open alerts between runs.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault(
    "NETWORK_DB_PATH",
    os.path.join(tempfile.mkdtemp(prefix="networkservice-test-"), "test.db"),
)
