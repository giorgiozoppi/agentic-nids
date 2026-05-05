#!/bin/bash
set -e

service ssh start
service apache2 start
service vsftpd start
service postfix start

echo "==========================================="
echo "  Victim Server 1 Ready"
echo "==========================================="
echo "Running Services:"
echo "  - SSH   (port 22)  root:victim123"
echo "  - HTTP  (port 80)  Apache"
echo "  - FTP   (port 21)  ftpuser:ftp123"
echo "  - SMTP  (port 25)  Postfix"
echo ""
echo "Network Info:"
ip addr show eth0 2>/dev/null | grep inet || hostname -I
echo ""
echo "Accounts: root:victim123  admin:admin  webmaster:password123"
echo "          ftpuser:ftp123  mailuser:mail123"
echo "==========================================="

exec tail -f /dev/null
