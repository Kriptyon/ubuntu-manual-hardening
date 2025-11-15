# Ubuntu Server Manual Hardening (24.04+)

A full manual hardening script for Ubuntu Server 24.04 LTS and newer.

This project implements production-grade hardening steps including:

- SSH hardening (root login disabled, verbose logs, safe password disable)
- UFW firewall baseline
- Kernel protections via sysctl
- Password policies & pwquality
- File permission hardening
- Disable insecure legacy services (telnet, ftp, rsh, etc.)
- auditd installation & enablement
- Optional IPv6 disable
- Backup of all modified config files

---

##  Usage

### 1. Make script executable

```bash
chmod +x src/manual-hardening-ubuntu24.sh
```

### 2. Run

```bash
sudo ./src/manual-hardening-ubuntu24.sh
```

- Backups stored at "/root/hardening-backups-YYYYMMDDHHMMSS"
