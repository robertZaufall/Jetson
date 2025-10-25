#!/usr/bin/env bash

set -euo pipefail

# Require root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: this script must be run as root (use sudo)." >&2
  exit 1
fi

REBOOT=${REBOOT:-0}

usage() {
  echo "Usage: $0 [--reboot|--no-reboot] [[--vnc-password=PASS]"
}

for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --vnc-password=*|--vnc-pass=*) VNC_PASSWORD="${arg#*=}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option '$arg'" >&2; usage; exit 1 ;;
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }

# Small helpers
apt_install_retry() {
  # Usage: apt_install_retry pkg1 [pkg2 ...]
  # Be resilient to transient DNS/network hiccups
  DEBIAN_FRONTEND=noninteractive apt-get update -y -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Acquire::Retries=3 "$@" || return 1
}

VNC_BACKEND="x11vnc"

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  TARGET_OS="${PRETTY_NAME:-${NAME:-unknown}}"
else
  TARGET_OS="$(uname -sr)"
fi
log "Target OS: ${TARGET_OS}; VNC backend: ${VNC_BACKEND}"


resolve_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  if logname >/dev/null 2>&1; then ln=$(logname 2>/dev/null || true); [ -n "$ln" ] && [ "$ln" != "root" ] && { printf '%s' "$ln"; return; }; fi
  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}
USERNAME="$(resolve_user)"
[ -n "$USERNAME" ] || { echo "ERROR: could not resolve a non-root user." >&2; exit 1; }
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"


log "1) Configure x11vnc remote desktop"
if [ -n "${VNC_PASSWORD:-}" ]; then
  GDM_CONF="/etc/gdm3/custom.conf"
  if [ -f "$GDM_CONF" ]; then
    if grep -qE '^[#[:space:]]*WaylandEnable[[:space:]]*=' "$GDM_CONF"; then
      sed -i -E 's/^[#[:space:]]*WaylandEnable[[:space:]]*=.*/WaylandEnable=false/' "$GDM_CONF" || true
    else
      grep -q '^\[daemon\]' "$GDM_CONF" || printf '\n[daemon]\n' >> "$GDM_CONF"
      printf 'WaylandEnable=false\n' >> "$GDM_CONF"
    fi
  fi
  ACCOUNTS_USER_FILE="/var/lib/AccountsService/users/$USERNAME"
  install -d -m 0755 /var/lib/AccountsService/users 2>/dev/null || true
  touch "$ACCOUNTS_USER_FILE"
  GNOME_SESSION=""
  if [ -f /usr/share/xsessions/gnome.desktop ]; then GNOME_SESSION=gnome; fi
  if [ -z "$GNOME_SESSION" ] && [ -f /usr/share/xsessions/ubuntu.desktop ]; then GNOME_SESSION=ubuntu; fi
  CURRENT_SESSION=""
  if [ -s "$ACCOUNTS_USER_FILE" ]; then
    CURRENT_SESSION=$(awk '
      /^[[:space:]]*(Session|XSession)[[:space:]]*=/{
        sub(/^[[:space:]]*(Session|XSession)[[:space:]]*=[[:space:]]*/, "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        if ($0 != "") { print $0; exit }
      }
    ' "$ACCOUNTS_USER_FILE" 2>/dev/null || true)
  fi
  if [ -n "$CURRENT_SESSION" ]; then
    log " - Existing desktop session entry: $CURRENT_SESSION"
  fi

  SESSION_TO_WRITE=""
  for candidate in "$CURRENT_SESSION" nvidia "$GNOME_SESSION" gnome gnome-xorg ubuntu ubuntu-xorg; do
    [ -n "$candidate" ] || continue
    if [ -f "/usr/share/xsessions/${candidate}.desktop" ]; then
      SESSION_TO_WRITE="$candidate"
      break
    fi
  done

  if [ -n "$SESSION_TO_WRITE" ]; then
    if [ "$SESSION_TO_WRITE" = "$CURRENT_SESSION" ] && [ -n "$CURRENT_SESSION" ]; then
      log " - Preserving AccountsService session '$SESSION_TO_WRITE'"
    else
      log " - Setting AccountsService session to '$SESSION_TO_WRITE'"
    fi

    if grep -q '^\[User\]' "$ACCOUNTS_USER_FILE"; then
      if grep -q '^[#[:space:]]*XSession[[:space:]]*=' "$ACCOUNTS_USER_FILE"; then
        sed -i -E 's/^[#[:space:]]*XSession[[:space:]]*=.*/XSession='"$SESSION_TO_WRITE"'/' "$ACCOUNTS_USER_FILE" || true
      else
        printf 'XSession=%s\n' "$SESSION_TO_WRITE" >> "$ACCOUNTS_USER_FILE"
      fi
    else
      printf '[User]\nXSession=%s\n' "$SESSION_TO_WRITE" > "$ACCOUNTS_USER_FILE"
    fi
  else
    log " - WARNING: could not locate a valid desktop session entry; leaving AccountsService untouched"
  fi

  apt_install_retry x11vnc || true

  VNC_PASS8=$(printf '%s' "$VNC_PASSWORD" | LC_ALL=C tr -cd '[:print:]' | cut -b 1-8)
  if [ -z "$VNC_PASS8" ]; then
    echo "ERROR: --vnc-password must contain at least one printable character." >&2
    exit 1
  fi

  x11vnc -storepasswd "$VNC_PASS8" /etc/x11vnc.pass >/dev/null 2>&1 || true
  printf '%s\n' "$VNC_PASS8" > "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
  chown "$USERNAME":"$USERNAME" "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
  chmod 600 /etc/x11vnc.pass && chown root:root /etc/x11vnc.pass

  cat >/usr/local/sbin/x11vnc-wrapper.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VNC_PASS_FILE="/etc/x11vnc.pass"
LOG_FILE="/var/log/x11vnc.log"

PREFERRED_USER="__PREFERRED_USER__"

resolve_display() {
  local user="$1"
  local sid disp type state
  while read -r sid _ usr _; do
    [ "$usr" = "$user" ] || continue
    type=$(loginctl show-session "$sid" -p Type 2>/dev/null | cut -d= -f2)
    state=$(loginctl show-session "$sid" -p State 2>/dev/null | cut -d= -f2)
    disp=$(loginctl show-session "$sid" -p Display 2>/dev/null | cut -d= -f2)
    if [ "$type" = "x11" ] && [ "$state" = "active" ] && [ -n "$disp" ]; then
      printf '%s\n' "$disp"
      return 0
    fi
  done < <(loginctl list-sessions --no-legend 2>/dev/null)
  return 1
}

USER_NAME=""
if [ -n "$PREFERRED_USER" ] && [ "$PREFERRED_USER" != "gdm" ]; then
  USER_NAME="$PREFERRED_USER"
fi
if [ -z "$USER_NAME" ]; then
USER_NAME=$(loginctl list-sessions --no-legend 2>/dev/null | awk '$3!="gdm" {print $3; exit}')
fi
[ -n "$USER_NAME" ] || USER_NAME="$(id -nu 1000 2>/dev/null || echo dgx)"
USER_UID=$(id -u "$USER_NAME")
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)

DISPLAY_VAL=""
if ! DISPLAY_VAL=$(resolve_display "$USER_NAME"); then
  if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
    if [ -r "/proc/$pid/environ" ]; then
      DISPLAY_VAL=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="DISPLAY"{print $2; exit}')
      [ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"
    fi
  fi
fi
[ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"

sock="/tmp/.X11-unix/X${DISPLAY_VAL#:}"
if [ ! -S "$sock" ]; then
  best=""
  for s in /tmp/.X11-unix/X*; do
    [ -S "$s" ] || continue
    n=${s##*/X}
    case "$n" in (*[!0-9]*) continue;; esac
    if [ -z "$best" ] || [ "$n" -gt "$best" ]; then best="$n"; fi
  done
  if [ -n "$best" ]; then DISPLAY_VAL=":$best"; sock="/tmp/.X11-unix/X$best"; fi
fi

for _ in $(seq 1 120); do
  [ -S "$sock" ] && break
  sleep 1
done

AUTH_ENV=""
if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
  if [ -r "/proc/$pid/environ" ]; then
    AUTH_ENV=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="XAUTHORITY"{print $2; exit}')
  fi
fi

AUTH_TMP="/run/x11vnc.${USER_UID}.auth"
rm -f "$AUTH_TMP" 2>/dev/null || true
if [ -n "$AUTH_ENV" ] && [ -f "$AUTH_ENV" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$AUTH_ENV' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
if [ ! -s "$AUTH_TMP" ] && [ -f "$HOME_DIR/.Xauthority" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$HOME_DIR/.Xauthority' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
chmod 600 "$AUTH_TMP" 2>/dev/null || true

AUTH_FILE="$AUTH_TMP"
if [ ! -s "$AUTH_FILE" ]; then
  AUTH_FILE="$HOME_DIR/.Xauthority"
fi
if [ ! -f "$AUTH_FILE" ]; then
  AUTH_FILE="/run/user/${USER_UID}/gdm/Xauthority"
fi

{
  echo "[x11vnc-wrapper] USER=$USER_NAME UID=$USER_UID HOME=$HOME_DIR"
  echo "[x11vnc-wrapper] DISPLAY=$DISPLAY_VAL AUTH=$AUTH_FILE"
} >> "$LOG_FILE" 2>&1 || true

su -s /bin/sh - "$USER_NAME" -c "DISPLAY='$DISPLAY_VAL' XAUTHORITY='${AUTH_ENV:-$HOME_DIR/.Xauthority}' xhost +SI:localuser:root" >>"$LOG_FILE" 2>&1 || true

AUTH_OPT=""
if [ -s "$AUTH_FILE" ]; then AUTH_OPT="-auth $AUTH_FILE"; fi

# -noshm prevents MIT-SHM BadAccess crashes on remote/virtual X servers.
exec /usr/bin/x11vnc \
  -display "$DISPLAY_VAL" \
  $AUTH_OPT \
  -forever -loop -noxdamage -noshm -repeat -xrandr \
  -rfbauth "$VNC_PASS_FILE" -rfbport 5900 -shared \
  -o "$LOG_FILE"
EOF
  sed -i -E "s#__PREFERRED_USER__#${USERNAME}#" /usr/local/sbin/x11vnc-wrapper.sh
  chmod 0755 /usr/local/sbin/x11vnc-wrapper.sh

  cat >/etc/systemd/system/x11vnc.service <<'EOF'
[Unit]
Description=Legacy VNC server for X11 (x11vnc)
Requires=display-manager.service
After=display-manager.service graphical.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/x11vnc-wrapper.sh
Restart=always
RestartSec=2

[Install]
WantedBy=graphical.target
EOF

  systemctl daemon-reload
  systemctl enable --now x11vnc.service || true

  log " - Set GDM to GNOME on X11 (WaylandEnable=false) and selected GNOME session. Reboot or log out/in to apply."

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -q '5900/tcp'; then
      ufw allow 5900/tcp || true
    fi
  fi
else
  log " - Skipping VNC setup (provide --vnc-password=... to enable x11vnc)"
fi
