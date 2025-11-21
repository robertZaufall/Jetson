#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: set_node.sh [--force-nm|--force-netplan] <node_number>

  node_number: 1 or 2 (defines the static CX7 addressing)

Behavior:
  - If NetworkManager is running (default Jetson desktop install), the CX7
    interfaces are configured via nmcli so Wi-Fi and other connections stay up.
  - If NetworkManager is unavailable or --force-netplan is passed, a Netplan
    file (/etc/netplan/40-cx7-p2p.yaml) is written and applied.
EOF
  exit 1
}

nm_ready() {
  command -v nmcli >/dev/null 2>&1 && nmcli general status >/dev/null 2>&1
}

ensure_nccl_socket_setting() {
  local bashrc_path="${HOME}/.bashrc"
  local export_line='export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0'

  if [[ ! -f "$bashrc_path" ]]; then
    touch "$bashrc_path"
    chmod 644 "$bashrc_path"
  fi

  if grep -Fqx "$export_line" "$bashrc_path"; then
    echo "NCCL_SOCKET_IFNAME already exported in $bashrc_path."
  else
    echo "$export_line" >>"$bashrc_path"
    echo "Added NCCL socket interface export to $bashrc_path."
  fi

  set +u
  # shellcheck disable=SC1090
  source "$bashrc_path"
  set -u
}

ensure_device_exists() {
  local ifname=$1
  if ip link show "$ifname" >/dev/null 2>&1; then
    return 0
  fi
  echo "WARNING: interface $ifname not present. Skipping its configuration." >&2
  return 1
}

configure_nm_connection() {
  local conn_name=$1
  local ifname=$2
  local ipv4_addr=$3
  local mtu_value=${4:-}

  ensure_device_exists "$ifname" || return 0

  if nmcli -t -f NAME connection show "$conn_name" >/dev/null 2>&1; then
    nmcli connection modify "$conn_name" connection.interface-name "$ifname"
  else
    nmcli connection add type ethernet ifname "$ifname" con-name "$conn_name" ipv4.method manual ipv4.addresses "$ipv4_addr"
  fi

  nmcli connection modify "$conn_name" \
    ipv4.method manual \
    ipv4.addresses "$ipv4_addr" \
    ipv4.never-default yes \
    ipv6.method ignore \
    connection.autoconnect yes

  if [[ -n "$mtu_value" ]]; then
    nmcli connection modify "$conn_name" 802-3-ethernet.mtu "$mtu_value"
  fi

  if ! nmcli connection up "$conn_name" >/dev/null 2>&1; then
    nmcli device connect "$ifname" >/dev/null 2>&1 || true
  fi

  echo "Configured NetworkManager connection '$conn_name' ($ifname -> $ipv4_addr)."
}

configure_with_nm() {
  local node_number=$1
  local addr_primary
  local addr_secondary
  local mtu_secondary=9000

  case "$node_number" in
    1)
      addr_primary="192.168.100.1/24"
      addr_secondary="192.168.200.1/24"
      ;;
    2)
      addr_primary="192.168.100.2/24"
      addr_secondary="192.168.200.2/24"
      ;;
  esac

  configure_nm_connection "cx7-node${node_number}-enp1s0f0np0" "enp1s0f0np0" "$addr_primary"
  configure_nm_connection "cx7-node${node_number}-enP2p1s0f0np0" "enP2p1s0f0np0" "$addr_secondary" "$mtu_secondary"
  echo "Static CX7 addresses applied via NetworkManager."
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

apply_netplan() {
  local node_number=$1
  local config_path="/etc/netplan/40-cx7-p2p.yaml"

  if [[ -f "$config_path" ]]; then
    echo "Netplan config already exists at $config_path. Remove it first if you need to regenerate."
    return 0
  fi

  mkdir -p "$(dirname "$config_path")"
  generate_yaml "$node_number" >"$config_path"
  chown root:root "$config_path"
  chmod 600 "$config_path"
  echo "Created $config_path for node $node_number."
  echo "Applying Netplan configuration..."
  if netplan apply; then
    echo "Netplan applied."
  else
    echo "netplan apply failed. Removing $config_path to avoid breaking networking."
    rm -f "$config_path"
    exit 1
  fi
}

main() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Try: sudo $0 <node_number>"
    exit 1
  fi

  ensure_nccl_socket_setting

  local force_nm=0
  local force_netplan=0
  local node_number=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-nm) force_nm=1 ;;
      --force-netplan) force_netplan=1 ;;
      -h|--help) usage ;;
      1|2)
        if [[ -n "$node_number" ]]; then
          usage
        fi
        node_number="$1"
        ;;
      *)
        usage
        ;;
    esac
    shift
  done

  if [[ -z "$node_number" ]]; then
    usage
  fi

  if (( force_nm == 1 && force_netplan == 1 )); then
    echo "Cannot combine --force-nm and --force-netplan." >&2
    exit 1
  fi

  case "$node_number" in
    1|2) ;;
    *) echo "Unsupported node number: $node_number" >&2; usage ;;
  esac

  local nm_available=0
  if nm_ready; then
    nm_available=1
  fi

  if (( force_nm == 1 )); then
    if (( nm_available == 0 )); then
      echo "ERROR: NetworkManager (nmcli) is unavailable; cannot honor --force-nm." >&2
      exit 1
    fi
    configure_with_nm "$node_number"
    exit 0
  fi

  if (( force_netplan == 0 && nm_available == 1 )); then
    configure_with_nm "$node_number"
    exit 0
  fi

  echo "NetworkManager unavailable or --force-netplan provided. Falling back to Netplan."
  apply_netplan "$node_number"
}

main "$@"
