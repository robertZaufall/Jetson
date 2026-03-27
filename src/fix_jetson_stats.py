#!/usr/bin/env python3
"""Clean reinstall jetson-stats and patch the page-5 engine crash."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


REMOVE_PATHS = [
    Path("/usr/local/lib/python3.10/dist-packages/jtop"),
    Path("/usr/local/bin/jtop"),
    Path("/usr/local/share/jetson_stats"),
    Path("/etc/systemd/system/jtop.service"),
    Path("/etc/profile.d/jtop_env.sh"),
    Path("/run/jtop.sock"),
    Path("/var/run/jtop.sock"),
]

DIST_INFO_GLOB = "/usr/local/lib/python3.10/dist-packages/jetson_stats-*.dist-info"
COMMON_PY = Path("/usr/local/lib/python3.10/dist-packages/jtop/gui/lib/common.py")

OLD_LABEL_FREQ = """def label_freq(frq, start='k'):\n    szw, _, k_unit = size_min(frq, start=start)\n"""
NEW_LABEL_FREQ = """def label_freq(frq, start='k'):\n    if frq is None:\n        return "N/A"\n    szw, _, k_unit = size_min(frq, start=start)\n"""

OLD_VALUE_TO_STRING = """def value_to_string(value, unit, type, func):\n    value, _, unit = func(value, start=unit)\n"""
NEW_VALUE_TO_STRING = """def value_to_string(value, unit, type, func):\n    if value is None:\n        return "N/A"\n    try:\n        value = float(value)\n    except (TypeError, ValueError):\n        return str(value)\n    value, _, unit = func(value, start=unit)\n"""


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def ensure_root() -> None:
    if os.geteuid() == 0:
        return
    os.execvp("sudo", ["sudo", "-E", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])


def remove_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    print(f"- removing {path}", flush=True)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def clean_old_install() -> None:
    subprocess.run(["systemctl", "stop", "jtop.service"], check=False)
    for path in REMOVE_PATHS:
        remove_path(path)
    for path in sorted(Path("/").glob(DIST_INFO_GLOB.lstrip("/"))):
        remove_path(path)


def reinstall() -> None:
    run(["pip3", "install", "-U", "pip", "setuptools", "wheel"])
    run([
        "pip3",
        "install",
        "--upgrade",
        "--force-reinstall",
        "git+https://github.com/rbonghi/jetson_stats.git",
    ])
    run(["jtop", "--install-service"])


def patch_common_py() -> None:
    if not COMMON_PY.exists():
        raise FileNotFoundError(f"missing expected file: {COMMON_PY}")
    text = COMMON_PY.read_text()

    if NEW_LABEL_FREQ not in text:
        if OLD_LABEL_FREQ not in text:
            raise RuntimeError("label_freq() patch anchor not found")
        text = text.replace(OLD_LABEL_FREQ, NEW_LABEL_FREQ, 1)

    if NEW_VALUE_TO_STRING not in text:
        if OLD_VALUE_TO_STRING not in text:
            raise RuntimeError("value_to_string() patch anchor not found")
        text = text.replace(OLD_VALUE_TO_STRING, NEW_VALUE_TO_STRING, 1)

    COMMON_PY.write_text(text)
    print(f"- patched {COMMON_PY}", flush=True)


def verify() -> None:
    run([
        "python3",
        "-c",
        "from jtop.gui.lib.common import unit_to_string,label_freq; "
        "print(unit_to_string(None,'k','Hz')); print(label_freq(None))",
    ])
    run([
        "python3",
        "-c",
        "import jtop; print(jtop.__version__); print(jtop.__file__)",
    ])
    subprocess.run(["systemctl", "status", "jtop.service", "--no-pager", "-l"], check=False)


def main() -> int:
    ensure_root()
    clean_old_install()
    reinstall()
    patch_common_py()
    verify()
    print("jetson-stats reinstall and patch complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
