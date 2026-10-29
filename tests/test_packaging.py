#
# VULNEX -Universal Security Visualization Library-
#
# File: test_packaging.py
# Author: Simon Roses Femerling
# Created: 2026-10-29
# Last Modified: 2026-10-29
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Every data file the library reads is shipped in the package (pip installs, not just the source tree)."""

import fnmatch
from pathlib import Path

from usecvislib.utils import tomllib  # tomli on Python 3.10

ROOT = Path(__file__).parent.parent
PACKAGE = ROOT / "src" / "usecvislib"


def test_package_data_covers_every_data_file():
    patterns = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"][
        "package-data"
    ]["usecvislib"]
    data_files = [
        p.relative_to(PACKAGE).as_posix()
        for p in PACKAGE.rglob("*")
        if p.is_file() and p.suffix in (".tml", ".toml", ".json") and "__pycache__" not in p.parts
    ]
    assert data_files
    # The shape gallery was missing from wheels, so pip installs had no shapes
    missing = [f for f in data_files if not any(fnmatch.fnmatch(f, pat) for pat in patterns)]
    assert missing == [], f"not in [tool.setuptools.package-data]: {missing}"
