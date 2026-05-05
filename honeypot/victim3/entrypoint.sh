#!/bin/bash
set -e

service ssh start
service lighttpd start

cd /opt/RedisHoneyPot && python3 server.py &

echo "==========================================="
echo "  Victim Server 3 Ready  (with Redis Honeypot)"
echo "==========================================="
echo "Running Services:"
echo "  - SSH    (port 22)    root:victim789"
echo "  - HTTP   (port 80)    Lighttpd"
echo "  - Redis  (port 6379)  honeypot"
echo ""
echo "Network Info:"
ip addr show eth0 2>/dev/null | grep inet || hostname -I
echo ""
echo "Accounts: root:victim789  redis:redis  cache:cache123  webadmin:admin123"
echo "Redis honeypot logs: /var/log/redis-honeypot/"
echo "==========================================="

exec tail -f /dev/null
