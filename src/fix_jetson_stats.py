#!/usr/bin/env python3
"""Cleanly install or reinstall jetson-stats/jtop and apply local patches."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent


INSTALL_ROOT = Path("/opt/jtop")
VENV_DIR = INSTALL_ROOT / "venv"
VENV_PYTHON = VENV_DIR / "bin/python"
VENV_PIP = VENV_DIR / "bin/pip"
VENV_JTOP = VENV_DIR / "bin/jtop"
WRAPPER_PATH = Path("/usr/local/bin/jtop")
SERVICE_PATH = Path("/etc/systemd/system/jtop.service")

REMOVE_PATHS = [
    INSTALL_ROOT,
    WRAPPER_PATH,
    SERVICE_PATH,
    Path("/etc/systemd/system/multi-user.target.wants/jtop.service"),
    Path("/etc/jtop"),
    Path("/var/log/jtop"),
    Path("/run/jtop.sock"),
    Path("/var/run/jtop.sock"),
]

REMOVE_GLOBS = [
    "/usr/local/lib/python*/dist-packages/jtop",
    "/usr/local/lib/python*/dist-packages/jetson_stats-*.dist-info",
    "/usr/local/lib/python*/site-packages/jtop",
    "/usr/local/lib/python*/site-packages/jetson_stats-*.dist-info",
    "/root/.local/lib/python*/site-packages/jtop",
    "/root/.local/lib/python*/site-packages/jetson_stats-*.dist-info",
]

OLD_LABEL_FREQ = """def label_freq(frq, start='k'):\n    szw, _, k_unit = size_min(frq, start=start)\n"""
NEW_LABEL_FREQ = """def label_freq(frq, start='k'):\n    if frq is None:\n        return "N/A"\n    szw, _, k_unit = size_min(frq, start=start)\n"""

OLD_VALUE_TO_STRING = """def value_to_string(value, unit, type, func):\n    value, _, unit = func(value, start=unit)\n"""
NEW_VALUE_TO_STRING = """def value_to_string(value, unit, type, func):\n    if value is None:\n        return "N/A"\n    try:\n        value = float(value)\n    except (TypeError, ValueError):\n        return str(value)\n    value, _, unit = func(value, start=unit)\n"""

VERSION_PATCHES = [
    (("36.4.4", "6.2.1"), ("36.4.3", "6.2")),
    (("38.2.0", "7.0"), ("36.4.4", "6.2.1")),
    (("38.2.1", "7.0 Rev.1"), ("38.2.0", "7.0")),
]


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, env=env)


def capture(cmd: list[str]) -> str:
    print("+", " ".join(cmd), flush=True)
    return subprocess.check_output(cmd, text=True).strip()


def warn(message: str) -> None:
    print(f"WARNING: {message}", flush=True)


def ensure_root() -> None:
    if os.geteuid() == 0:
        return
    os.execvp(
        "sudo",
        ["sudo", "-E", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install jetson-stats/jtop in /opt/jtop and apply local patches."
    )
    parser.add_argument(
        "--user",
        help="Add this user to the jtop group after installing the service.",
    )
    return parser.parse_args()


def remove_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    print(f"- removing {path}", flush=True)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def remove_glob(pattern: str) -> None:
    for path in sorted(Path("/").glob(pattern.lstrip("/"))):
        remove_path(path)


def ensure_prerequisites() -> None:
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(
        [
            "apt-get",
            "update",
            "-y",
            "-o",
            "Acquire::Retries=3",
            "-o",
            "Acquire::http::Timeout=15",
            "-o",
            "Acquire::https::Timeout=15",
        ],
        env=env,
    )
    run(
        [
            "apt-get",
            "install",
            "-y",
            "-o",
            "Acquire::Retries=3",
            "git",
            "python3-pip",
            "python3-venv",
        ],
        env=env,
    )


def clean_old_install() -> None:
    subprocess.run(["systemctl", "stop", "jtop.service"], check=False)
    subprocess.run(["systemctl", "disable", "jtop.service"], check=False)
    for path in REMOVE_PATHS:
        remove_path(path)
    for pattern in REMOVE_GLOBS:
        remove_glob(pattern)


def install_into_venv() -> None:
    INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
    run(["python3", "-m", "venv", str(VENV_DIR)])
    run([str(VENV_PIP), "install", "--upgrade", "pip", "setuptools", "wheel"])
    run([str(VENV_PIP), "install", "--upgrade", "nvidia-ml-py", "nvidia-ml-py3"])
    run(
        [
            str(VENV_PIP),
            "install",
            "--upgrade",
            "--force-reinstall",
            "git+https://github.com/rbonghi/jetson_stats.git",
        ]
    )


def write_wrapper() -> None:
    WRAPPER_PATH.write_text(
        dedent(
            f"""\
            #!/usr/bin/env bash
            exec {VENV_JTOP} "$@"
            """
        )
    )
    WRAPPER_PATH.chmod(0o755)


def ensure_group_membership(user: str | None) -> None:
    if subprocess.run(["getent", "group", "jtop"], stdout=subprocess.DEVNULL, check=False).returncode != 0:
        run(["groupadd", "--system", "jtop"])

    if not user:
        return

    groups = capture(["id", "-nG", user]).split()
    if "jtop" not in groups:
        run(["usermod", "-aG", "jtop", user])


def write_service() -> None:
    SERVICE_PATH.write_text(
        dedent(
            f"""\
            [Unit]
            Description=Jetson Stats (jtop)
            After=network.target multi-user.target

            [Service]
            Type=simple
            Environment=JTOP_SERVICE=True
            ExecStart={VENV_JTOP} --force
            Restart=on-failure
            RestartSec=2s
            TimeoutStartSec=30s
            TimeoutStopSec=30s
            StandardOutput=journal
            StandardError=journal
            WorkingDirectory={INSTALL_ROOT}
            UMask=007
            Group=jtop
            RuntimeDirectory=jtop
            RuntimeDirectoryMode=0770

            [Install]
            WantedBy=multi-user.target
            """
        )
    )


def locate_module_file(module: str) -> Path:
    path = capture([str(VENV_PYTHON), "-c", f"import {module} as m; print(m.__file__)"])
    return Path(path)


def patch_common_py(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing expected file: {path}")

    text = path.read_text()
    changed = False

    if NEW_LABEL_FREQ not in text:
        if OLD_LABEL_FREQ in text:
            text = text.replace(OLD_LABEL_FREQ, NEW_LABEL_FREQ, 1)
            changed = True
        else:
            warn(f"label_freq() patch anchor not found in {path}")

    if NEW_VALUE_TO_STRING not in text:
        if OLD_VALUE_TO_STRING in text:
            text = text.replace(OLD_VALUE_TO_STRING, NEW_VALUE_TO_STRING, 1)
            changed = True
        else:
            warn(f"value_to_string() patch anchor not found in {path}")

    if changed:
        path.write_text(text)
        print(f"- patched {path}", flush=True)
    else:
        print(f"- no page-5 patch changes needed in {path}", flush=True)


def insert_mapping(text: str, mapping: tuple[str, str], anchor: tuple[str, str]) -> str:
    mapping_line = f'    "{mapping[0]}": "{mapping[1]}",'
    anchor_line = f'    "{anchor[0]}": "{anchor[1]}",'
    if mapping_line in text:
        return text
    if anchor_line not in text:
        warn(f"mapping anchor not found for {mapping[0]} in jetson_variables.py")
        return text
    return text.replace(anchor_line, f"{mapping_line}\n{anchor_line}", 1)


def patch_version_mapping(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing expected file: {path}")

    text = path.read_text()
    updated = text
    for mapping, anchor in VERSION_PATCHES:
        updated = insert_mapping(updated, mapping, anchor)

    if updated != text:
        path.write_text(updated)
        print(f"- patched {path}", flush=True)
    else:
        print(f"- no version-mapping changes needed in {path}", flush=True)


def enable_service() -> None:
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "jtop.service"])


def verify() -> None:
    run(
        [
            str(VENV_PYTHON),
            "-c",
            (
                "from jtop.gui.lib.common import unit_to_string, label_freq; "
                "print(unit_to_string(None, 'k', 'Hz')); print(label_freq(None))"
            ),
        ]
    )
    run([str(VENV_PYTHON), "-c", "import jtop; print(jtop.__version__); print(jtop.__file__)"])
    if subprocess.run(["systemctl", "is-active", "--quiet", "jtop.service"], check=False).returncode != 0:
        subprocess.run(["journalctl", "-u", "jtop.service", "-n", "80", "--no-pager"], check=False)
        raise RuntimeError("jtop.service is not active")
    subprocess.run(["systemctl", "status", "jtop.service", "--no-pager", "-l"], check=False)


def main() -> int:
    args = parse_args()
    ensure_root()
    ensure_prerequisites()
    clean_old_install()
    install_into_venv()
    write_wrapper()
    ensure_group_membership(args.user)
    write_service()
    patch_common_py(locate_module_file("jtop.gui.lib.common"))
    patch_version_mapping(locate_module_file("jtop.core.jetson_variables"))
    enable_service()
    verify()
    print("jetson-stats install and patch complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
