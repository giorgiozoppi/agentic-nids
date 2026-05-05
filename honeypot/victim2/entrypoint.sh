#!/bin/bash
set -e

service ssh start
service php8.1-fpm start 2>/dev/null || service php-fpm start
service nginx start
service vsftpd start
service postfix start

cd /opt/pghoney && python3 pghoney.py &

echo "==========================================="
echo "  Victim Server 2 Ready  (with PGHoney)"
echo "==========================================="
echo "Running Services:"
echo "  - SSH        (port 22)    root:victim456"
echo "  - HTTP       (port 80)    Nginx"
echo "  - FTP        (port 21)    ftpuser:ftp456"
echo "  - SMTP       (port 25)    Postfix"
echo "  - PostgreSQL (port 5432)  pghoney honeypot"
echo ""
echo "Network Info:"
ip addr show eth0 2>/dev/null | grep inet || hostname -I
echo ""
echo "Accounts: root:victim456  postgres:postgres  dbadmin:dbadmin123"
echo "          webuser:web123  ftpuser:ftp456"
echo "PGHoney logs: /var/log/pghoney/pghoney.log"
echo "==========================================="

exec tail -f /dev/null
