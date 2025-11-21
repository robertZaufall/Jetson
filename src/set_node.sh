#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <node_number>"
  echo "  node_number: 1 or 2"
  exit 1
}

generate_yaml() {
  local node_number=$1

  case "$node_number" in
    1)
      cat <<'EOF'
network:
  version: 2
  ethernets:
    # First Half (Standard)
    enp1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.1/24
    # Second Half (The enP2 ports you asked about)
    enP2p1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.200.1/24
      mtu: 9000  # Recommended for RoCE
EOF
      ;;
    2)
      cat <<'EOF'
network:
  version: 2
  ethernets:
    # First Half
    enp1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.2/24
    # Second Half
    enP2p1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.200.2/24
      mtu: 9000
EOF
      ;;
    *)
      usage
      ;;
  esac
}

main() {
  if [[ $# -ne 1 ]]; then
    usage
  fi

  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Try: sudo $0 <node_number>"
    exit 1
  fi

  local node_number=$1
  local config_path="/etc/netplan/40-cx7-p2p.yaml"

  case "$node_number" in
    1|2)
      ;;
    *)
      echo "Unsupported node number: $node_number"
      usage
      ;;
  esac

  if [[ -f "$config_path" ]]; then
    echo "Netplan config already exists at $config_path. Skipping."
    exit 0
  fi

  mkdir -p "$(dirname "$config_path")"
  generate_yaml "$node_number" >"$config_path"
  chown root:root "$config_path"
  chmod 600 "$config_path"
  echo "Created $config_path for node $node_number."
  echo "Applying Netplan configuration..."
  netplan apply
  echo "Netplan applied."
}

main "$@"
