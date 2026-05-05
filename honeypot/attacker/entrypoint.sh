#!/bin/bash
set -e

service ssh start

echo "==========================================="
echo "  Attacker Container Ready"
echo "==========================================="
echo "Installed Tools:"
echo "  - nmap (network scanner)"
echo "  - ettercap (MITM attacks)"
echo "  - metasploit (exploit framework)"
echo "  - sqlmap (SQL injection)"
echo "  - hydra (password cracker)"
echo "  - nikto (web scanner)"
echo "  - and many more..."
echo ""
echo "Network Info:"
ip addr show eth0 2>/dev/null | grep inet || hostname -I
echo ""
echo "Targets (resolve via K8s DNS):"
echo "  - victim1  (SSH:22, HTTP:80, FTP:21, SMTP:25)"
echo "  - victim2  (SSH:22, HTTP:80, FTP:21, SMTP:25, PG:5432)"
echo "  - victim3  (SSH:22, HTTP:80, Redis:6379)"
echo "==========================================="

exec tail -f /dev/null
