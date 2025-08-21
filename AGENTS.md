# Repository Guidelines

## Project Structure & Module Organization
- Root docs: `README.md`, `Installation.md`, `ROS.md`, `JetsonContainers.md`, `Registry.md`, `K3s.md`.
- Scripts: `src/` contains Bash utilities for setup and flashing (e.g., `start.sh`, `orin_nano.sh`, `orin_nx.sh`) and a K3s test manifest `test_k3s.yaml`.
- Assets: `images/` holds diagrams and screenshots used by docs.

## Build, Test, and Development Commands
- Run system setup (Jetson host): `sudo bash src/start.sh --help`
  - Examples: `sudo bash src/start.sh --vnc-password=secret --k3s`, `sudo bash src/start.sh --swap-size=16G`.
- Flash helpers (on x86 host with JetPack SDK):
  - Orin Nano: `bash src/orin_nano.sh <user> <pass> <hostname>`
  - Orin NX: `bash src/orin_nx.sh <user> <pass> <hostname>`
- K3s smoke test (on device): `kubectl apply -f src/test_k3s.yaml` then `kubectl exec -it torch -- python3`.

## Coding Style & Naming Conventions
- Bash: `set -euo pipefail`; prefer functions; use `snake_case` for variables/functions; quote variables; use long flags.
- Filenames: lowercase with hyphens/underscores (e.g., `start.sh`, `test_k3s.yaml`).
- Markdown: concise sections with command blocks; link local files with relative paths.
- Linting (recommended): `shellcheck src/*.sh` and `shfmt -i 2 -bn -ci -w src` when available.

## Testing Guidelines
- Scripts: dry-run by invoking with `--help`; validate on a spare Jetson before wide rollout.
- K3s: ensure `kubectl get nodes` is Ready; deploy `src/test_k3s.yaml` and verify GPU with `torch.cuda.is_available()`.
- Docs: ensure examples execute as written on JetPack 6.2+/Ubuntu (Jetson).

## Commit & Pull Request Guidelines
- Commits: imperative, concise subject (≤ 72 chars). Examples: `fix: docker config for registry mirror`, `feat: add VNC password setup`.
- PRs: include purpose, environment (device, JetPack), steps to validate, and screenshots/logs where relevant; link issues.
- Keep changes scoped; do not mix unrelated edits (docs vs. scripts) in the same PR.

## Security & Configuration Tips
- VNC: `start.sh` can set a VNC password; avoid weak 8‑char defaults in production; consider enabling encryption.
- Keyring: `start.sh` may create an unencrypted keyring for non-interactive setups—review policy for your environment.
- Docker/Registry: manage certificates and mirrors as in `Registry.md`; do not commit secrets.

