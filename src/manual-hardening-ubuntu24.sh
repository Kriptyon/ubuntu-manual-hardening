#!/bin/bash

# manual-hardening-ubuntu24.sh
# Professional manual hardening script for Ubuntu Server 24.04+.
# Author: Sebastián García
# Usage: sudo ./manual-hardening-ubuntu24.sh
# NOTE (SAFETY): This script attempts to be safe and idempotent.
# - It WILL NOT disable SSH password authentication if you are connected via SSH and no authorized key is detected.
# - Review the script before running on production systems.


set -euo pipefail

# Configuration (tweakable)

# port name used by UFW (OpenSSH service / port)
ALLOW_SSH_PORT="22"                 
# set to true to disable IPv6 via sysctl
DISABLE_IPV6=false                  
BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d%H%M%S)"
SERVICES_TO_REMOVE=(telnetd ftp rsh-server rsh-client tftp avahi-daemon cups rpcbind)
PW_MAX_DAYS=90
PW_MIN_DAYS=7
PW_WARN_AGE=14
PW_MINLEN=12
# -------------------------

echo "Ubuntu 24+ Manual Hardening — START"
echo "Backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# helper: check command exists
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# safe-edit: backup and sed
safe_sed() {
  local file="$1"; shift
  if [ -f "$file" ]; then
    cp -a "$file" "$BACKUP_DIR/$(basename "$file").bak"
    sed -ri "$@" "$file"
  else
    echo "WARN: $file not found, skipping safe_sed"
  fi
}

# 1) Update & full upgrade
echo "[1/12] Updating package lists and upgrading distribution..."
apt update -y
apt full-upgrade -y

# 2) Enable unattended security upgrades
echo "[2/12] Ensuring unattended-upgrades is installed and configured..."
if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
  apt install -y unattended-upgrades
fi
# enable with dpkg-reconfigure (non-interactive)
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades || true

# 3) UFW: default deny incoming, allow outgoing, allow OpenSSH
echo "[3/12] Configuring UFW (firewall)..."
if cmd_exists ufw; then
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "$ALLOW_SSH_PORT"/tcp || ufw allow OpenSSH || true
  ufw --force enable
else
  echo "INFO: ufw not installed, installing..."
  apt install -y ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "$ALLOW_SSH_PORT"/tcp || ufw allow OpenSSH || true
  ufw --force enable
fi

# 4) SSH hardening
SSH_CONF="/etc/ssh/sshd_config"
echo "[4/12] Hardening SSH configuration..."

if [ -f "$SSH_CONF" ]; then
  cp -a "$SSH_CONF" "$BACKUP_DIR/sshd_config.bak"

  # Ensure PermitRootLogin no
  if grep -qE '^\s*PermitRootLogin' "$SSH_CONF"; then
    safe_sed "$SSH_CONF" 's/^\s*PermitRootLogin.*/PermitRootLogin no/'
  else
    echo "PermitRootLogin no" >> "$SSH_CONF"
  fi

  # Ensure X11Forwarding no
  if grep -qE '^\s*X11Forwarding' "$SSH_CONF"; then
    safe_sed "$SSH_CONF" 's/^\s*X11Forwarding.*/X11Forwarding no/'
  else
    echo "X11Forwarding no" >> "$SSH_CONF"
  fi

  # Ensure LogLevel VERBOSE (increase logging)
  if grep -qE '^\s*LogLevel' "$SSH_CONF"; then
    safe_sed "$SSH_CONF" 's/^\s*LogLevel.*/LogLevel VERBOSE/'
  else
    echo "LogLevel VERBOSE" >> "$SSH_CONF"
  fi

  # SAFETY: Do NOT disable PasswordAuthentication if we are connected via SSH and no public key exists.
  disable_pwd_auth=true
  if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_CLIENT:-}" ]; then
    # We're on an SSH session — check for an authorized_keys for the current user
    CUR_USER="$(whoami)"
    AUTH_KEY_PATH="${HOME}/.ssh/authorized_keys"
    if [ ! -f "$AUTH_KEY_PATH" ]; then
      echo "WARNING: No ${AUTH_KEY_PATH} found for user ${CUR_USER}. Will NOT disable PasswordAuthentication to avoid lockout."
      disable_pwd_auth=false
    else
      # authorized_keys exists; ensure it contains at least one non-empty line
      if [ "$(grep -cve '^\s*$' "$AUTH_KEY_PATH" || true)" -eq 0 ]; then
        echo "WARNING: ${AUTH_KEY_PATH} is empty. Will NOT disable PasswordAuthentication to avoid lockout."
        disable_pwd_auth=false
      fi
    fi
  fi

  if [ "$disable_pwd_auth" = true ]; then
    # set PasswordAuthentication no
    if grep -qE '^\s*PasswordAuthentication' "$SSH_CONF"; then
      safe_sed "$SSH_CONF" 's/^\s*PasswordAuthentication.*/PasswordAuthentication no/'
    else
      echo "PasswordAuthentication no" >> "$SSH_CONF"
    fi
    echo "PasswordAuthentication disabled (safe to disable detected)."
  else
    echo "PasswordAuthentication left unchanged (safety: SSH key not detected or running over SSH)."
  fi

  # Restart SSH daemon gracefully (only if systemd unit exists)
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    systemctl restart sshd
  elif systemctl list-unit-files | grep -q '^ssh\.service'; then
    systemctl restart ssh
  else
    echo "INFO: Could not find sshd/ssh systemd unit to restart. Please restart SSH manually."
  fi
else
  echo "ERROR: $SSH_CONF not found; skipping SSH hardening."
fi

# 5) Remove insecure/legacy services
echo "[5/12] Removing insecure legacy/network services (if installed)..."
for svc in "${SERVICES_TO_REMOVE[@]}"; do
  if dpkg -l | grep -qi "$svc"; then
    echo " - Removing package(s) related to: $svc"
    apt purge -y "$svc" || true
  else
    echo " - $svc not installed, skipping."
  fi
done
apt autoremove -y

# 6) Password & account policies: login.defs + pwquality
echo "[6/12] Applying password aging and complexity policies..."
if [ -f /etc/login.defs ]; then
  cp -a /etc/login.defs "$BACKUP_DIR/login.defs.bak"
  # Ensure PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE
  if grep -q '^PASS_MAX_DAYS' /etc/login.defs; then
    safe_sed /etc/login.defs "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t$PW_MAX_DAYS/"
  else
    echo -e "PASS_MAX_DAYS\t$PW_MAX_DAYS" >> /etc/login.defs
  fi
  if grep -q '^PASS_MIN_DAYS' /etc/login.defs; then
    safe_sed /etc/login.defs "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t$PW_MIN_DAYS/"
  else
    echo -e "PASS_MIN_DAYS\t$PW_MIN_DAYS" >> /etc/login.defs
  fi
  if grep -q '^PASS_WARN_AGE' /etc/login.defs; then
    safe_sed /etc/login.defs "s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t$PW_WARN_AGE/"
  else
    echo -e "PASS_WARN_AGE\t$PW_WARN_AGE" >> /etc/login.defs
  fi
fi

# pwquality
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
  apt install -y libpam-pwquality
fi

PWQ_CONF="/etc/security/pwquality.conf"
cp -a "$PWQ_CONF" "$BACKUP_DIR/pwquality.conf.bak" || true
# ensure settings present (idempotent append if not present)
grep -q '^minlen' "$PWQ_CONF" || echo "minlen = $PW_MINLEN" >> "$PWQ_CONF"
grep -q '^dcredit' "$PWQ_CONF" || echo "dcredit = -1" >> "$PWQ_CONF"
grep -q '^ucredit' "$PWQ_CONF" || echo "ucredit = -1" >> "$PWQ_CONF"
grep -q '^ocredit' "$PWQ_CONF" || echo "ocredit = -1" >> "$PWQ_CONF"
grep -q '^lcredit' "$PWQ_CONF" || echo "lcredit = -1" >> "$PWQ_CONF"

# 7) Critical permissions on key files
echo "[7/12] Hardening file permissions..."
[ -f /etc/shadow ] && chmod 600 /etc/shadow || true
[ -f /etc/passwd ] && chmod 644 /etc/passwd || true
[ -f /etc/ssh/sshd_config ] && chmod 600 /etc/ssh/sshd_config || true

# 8) Install & enable auditd
echo "[8/12] Installing and enabling auditd for auditing..."
if ! dpkg -s auditd >/dev/null 2>&1; then
  apt install -y auditd audispd-plugins
fi
systemctl enable --now auditd

# 9) Kernel hardening via sysctl.d
echo "[9/12] Applying kernel hardening (sysctl.d)..."
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
cat > "$SYSCTL_FILE" <<'EOF'
# Kernel & networking hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
EOF
sysctl --system

# 10) Optional: disable IPv6 if user configured
if [ "$DISABLE_IPV6" = true ]; then
  echo "[10/12] Disabling IPv6 (user opted in)..."
  SYSCTL_IPV6="/etc/sysctl.d/99-disable-ipv6.conf"
  cat > "$SYSCTL_IPV6" <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sysctl --system
else
  echo "[10/12] IPv6 left enabled (DISABLE_IPV6=false)."
fi

# 11) Disable core dumps (limits.conf)
echo "[11/12] Disabling core dumps for security..."
LIMITS_FILE="/etc/security/limits.conf"
cp -a "$LIMITS_FILE" "$BACKUP_DIR/limits.conf.bak" || true
grep -q 'hard core 0' "$LIMITS_FILE" || echo '* hard core 0' >> "$LIMITS_FILE"
ulimit -S -c 0 || true

# 12) Protect GRUB configuration files
echo "[12/12] Harden GRUB files permissions..."
if [ -d /etc/grub.d ]; then
  chmod 600 /etc/grub.d/* || true
fi

# Final: report summary and tips
echo "=== HARDENING COMPLETE ==="
echo "Backups of modified files (where applicable) are in: $BACKUP_DIR"
echo ""
echo "IMPORTANT POST-RUN CHECKS:"
echo " - Verify you still can SSH (if you ran remotely)."
echo " - If you intend to disable PasswordAuthentication, ensure SSH key-based access is configured BEFORE running the script."
echo " - Review $BACKUP_DIR for originals of modified files."
echo ""
echo "Suggested next steps (not automated):"
echo " - Configure Fail2Ban with a sensible jail for OpenSSH."
echo " - Install and configure unattended-upgrades (policy review)."
echo " - Run CIS Benchmark scanner and remediate remaining findings."
echo ""
exit 0
