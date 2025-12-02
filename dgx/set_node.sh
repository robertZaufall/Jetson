#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: set_node.sh [--force-nm|--force-netplan] [--cleanup] <node_number>

  node_number: 1 or 2 (defines the static CX7 addressing)
  --cleanup: remove NetworkManager connections, Netplan file, and NCCL env change

Behavior:
  - Single-cable CX7 setup with manual static IPv4 addresses on both connectors,
    ports 0 and 1 (enp1s0f0np0, enp1s0f1np1, enP2p1s0f0np0, enP2p1s0f1np1)
    using the DGX Spark playbook IPs. No bonding used.
  - If NetworkManager is running (default Jetson desktop install), the CX7
    interfaces are configured via nmcli so Wi-Fi and other connections stay up.
  - If NetworkManager is unavailable or --force-netplan is passed, a Netplan
    file (/etc/netplan/40-cx7-p2p.yaml) is written and applied.
  - --cleanup removes the changes made by this script. No node_number required.
EOF
  exit 1
}

nm_ready() {
  command -v nmcli >/dev/null 2>&1 && nmcli general status >/dev/null 2>&1
}

ensure_nccl_socket_setting() {
  local bashrc_path="${HOME}/.bashrc"
  local export_line='export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1,enP2p1s0f0np0,enP2p1s0f1np1'
  local old_export_lines=(
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0,enP2p1s0f1np1'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1,enP2p1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0'
  )

  if [[ ! -f "$bashrc_path" ]]; then
    touch "$bashrc_path"
    chmod 644 "$bashrc_path"
  fi

  for legacy_line in "${old_export_lines[@]}"; do
    if grep -Fqx "$legacy_line" "$bashrc_path"; then
      local tmp_cleanup
      tmp_cleanup=$(mktemp)
      grep -Fvx "$legacy_line" "$bashrc_path" >"$tmp_cleanup"
      mv "$tmp_cleanup" "$bashrc_path"
      echo "Removed legacy NCCL socket export from $bashrc_path: $legacy_line"
    fi
  done

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

cleanup_nccl_socket_setting() {
  local bashrc_path="${HOME}/.bashrc"
  local export_line='export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1,enP2p1s0f0np0,enP2p1s0f1np1'
  local old_export_lines=(
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0,enP2p1s0f1np1'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enp1s0f1np1,enP2p1s0f0np0'
    'export NCCL_SOCKET_IFNAME=enp1s0f0np0,enP2p1s0f0np0'
  )

  if [[ ! -f "$bashrc_path" ]]; then
    return 0
  fi

  local pattern_found=0
  if grep -Fqx "$export_line" "$bashrc_path"; then
    pattern_found=1
  else
    for legacy_line in "${old_export_lines[@]}"; do
      if grep -Fqx "$legacy_line" "$bashrc_path"; then
        pattern_found=1
        break
      fi
    done
  fi

  if (( pattern_found == 0 )); then
    return 0
  fi

  local tmp
  tmp=$(mktemp)
  grep -Fvx -e "$export_line" -e "${old_export_lines[@]}" "$bashrc_path" >"$tmp"
  mv "$tmp" "$bashrc_path"
  echo "Removed NCCL socket export from $bashrc_path."
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
  local addr_port0
  local addr_port1
  local addr_port2
  local addr_port3
  local mtu_port1=9000
  local mtu_port3=9000

  case "$node_number" in
    1)
      addr_port0="192.168.100.10/24"
      addr_port1="192.168.100.14/24"
      addr_port2="192.168.200.12/24"
      addr_port3="192.168.200.16/24"
      ;;
    2)
      addr_port0="192.168.100.11/24"
      addr_port1="192.168.100.15/24"
      addr_port2="192.168.200.13/24"
      addr_port3="192.168.200.17/24"
      ;;
  esac

  configure_nm_connection "cx7-node${node_number}-enp1s0f0np0" "enp1s0f0np0" "$addr_port0"
  configure_nm_connection "cx7-node${node_number}-enP2p1s0f0np0" "enP2p1s0f0np0" "$addr_port1"
  configure_nm_connection "cx7-node${node_number}-enp1s0f1np1" "enp1s0f1np1" "$addr_port2" "$mtu_port1"
  configure_nm_connection "cx7-node${node_number}-enP2p1s0f1np1" "enP2p1s0f1np1" "$addr_port3" "$mtu_port3"
  echo "Static CX7 addresses applied via NetworkManager (both ports on both connectors)."
}

generate_yaml() {
  local node_number=$1

  case "$node_number" in
    1)
      cat <<'EOF'
network:
  version: 2
  ethernets:
    enp1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.10/24
    enP2p1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.14/24
    enp1s0f1np1:
      dhcp4: false
      addresses:
        - 192.168.200.12/24
      mtu: 9000
    enP2p1s0f1np1:
      dhcp4: false
      addresses:
        - 192.168.200.16/24
      mtu: 9000
EOF
      ;;
    2)
      cat <<'EOF'
network:
  version: 2
  ethernets:
    enp1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.11/24
    enP2p1s0f0np0:
      dhcp4: false
      addresses:
        - 192.168.100.15/24
    enp1s0f1np1:
      dhcp4: false
      addresses:
        - 192.168.200.13/24
      mtu: 9000
    enP2p1s0f1np1:
      dhcp4: false
      addresses:
        - 192.168.200.17/24
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

cleanup_netplan() {
  local config_path="/etc/netplan/40-cx7-p2p.yaml"

  if [[ ! -f "$config_path" ]]; then
    echo "No Netplan file to remove at $config_path."
    return 0
  fi

  rm -f "$config_path"
  echo "Removed $config_path."
  if command -v netplan >/dev/null 2>&1; then
    if netplan apply; then
      echo "Re-applied Netplan after removal."
    else
      echo "WARNING: netplan apply failed after cleanup." >&2
    fi
  fi
}

cleanup_nm() {
  if ! nm_ready; then
    echo "NetworkManager unavailable; skipping nmcli cleanup."
    return 0
  fi

  local connections=(
    "cx7-node1-enp1s0f0np0"
    "cx7-node1-enp1s0f1np1"
    "cx7-node1-enP2p1s0f0np0"
    "cx7-node1-enP2p1s0f1np1"
    "cx7-node2-enp1s0f0np0"
    "cx7-node2-enp1s0f1np1"
    "cx7-node2-enP2p1s0f0np0"
    "cx7-node2-enP2p1s0f1np1"
  )

  local ifaces=("enp1s0f0np0" "enp1s0f1np1" "enP2p1s0f0np0" "enP2p1s0f1np1")

  for conn in "${connections[@]}"; do
    if nmcli -t -f NAME connection show "$conn" >/dev/null 2>&1; then
      nmcli connection down "$conn" >/dev/null 2>&1 || true
      nmcli connection delete "$conn" >/dev/null
      echo "Deleted NetworkManager connection '$conn'."
    fi
  done

  for iface in "${ifaces[@]}"; do
    if ensure_device_exists "$iface"; then
      ip addr flush dev "$iface" >/dev/null 2>&1 || true
    fi
  done
}

cleanup_all() {
  cleanup_nccl_socket_setting
  cleanup_nm
  cleanup_netplan
  echo "Cleanup complete."
}

main() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Try: sudo $0 <node_number>"
    exit 1
  fi

  local force_nm=0
  local force_netplan=0
  local node_number=""
  local cleanup=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-nm) force_nm=1 ;;
      --force-netplan) force_netplan=1 ;;
      --cleanup) cleanup=1 ;;
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

  if (( cleanup == 1 )); then
    cleanup_all
    exit 0
  fi

  ensure_nccl_socket_setting

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
