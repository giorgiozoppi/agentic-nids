# Honeypot Quick Start Guide

## 🚀 Start the Honeypot Environment

```bash
cd /home/fenix/projects/agentic-nids/honeypot
./start.sh
```

This will:
1. Install Docker Loki plugin (if not already installed)
2. Build all containers
3. Start the honeypot network
4. Display access information

## 📊 Network Architecture

```
172.20.0.0/24 - Honeypot Network
├── 172.20.0.10  - Attacker (Kali Linux)
├── 172.20.0.20  - Victim 1 (Apache, FTP, SMTP, SSH)
├── 172.20.0.30  - Victim 2 (Nginx, FTP, SMTP, PGHoney, SSH)
├── 172.20.0.40  - Victim 3 (Lighttpd, Redis Honeypot, SSH)
├── 172.20.0.50  - Loki (Log aggregation)
└── 172.20.0.51  - Grafana (Log visualization)
```

## 🎯 Quick Access

### SSH Access
```bash
# Attacker
ssh root@localhost -p 2201   # password: attacker123

# Victims
ssh root@localhost -p 2202   # victim1 - password: victim123
ssh root@localhost -p 2203   # victim2 - password: victim456
ssh root@localhost -p 2204   # victim3 - password: victim789
```

### Web Interfaces
- Victim 1: http://localhost:8081
- Victim 2: http://localhost:8082
- Victim 3: http://localhost:8083
- **Grafana**: http://localhost:3000 (logs dashboard)

### Honeypot Services
```bash
# PostgreSQL Honeypot (pghoney)
psql -h localhost -p 5433 -U postgres -d honeypot

# Redis Honeypot
redis-cli -h localhost -p 6380
```

## 🧪 Quick Attack Scenarios

### 1. Network Scan (from attacker)
```bash
ssh root@localhost -p 2201
nmap -sV 172.20.0.20-40
```

### 2. Web Exploitation
```bash
# From attacker
nikto -h http://172.20.0.20
sqlmap -u "http://172.20.0.20/index.php?cmd=test"

# From host
curl "http://localhost:8081/index.php?cmd=whoami"
```

### 3. Database Attacks (PostgreSQL Honeypot)
```bash
# From attacker
psql -h 172.20.0.30 -U postgres

# From host
psql -h localhost -p 5433 -U postgres -d honeypot
# All commands logged in /var/log/pghoney/
```

### 4. Redis Attacks (Redis Honeypot)
```bash
# From attacker
redis-cli -h 172.20.0.40

# From host
redis-cli -h localhost -p 6380
INFO
KEYS *
```

## 📈 View Logs in Grafana

1. Open http://localhost:3000
2. Go to "Explore" (compass icon)
3. Select "Loki" as data source
4. Query examples:
   ```
   {container="victim1"}
   {container="victim2"}
   {container="victim3"}
   {job="honeypot"}
   ```

## 🔍 Monitor with NFStream

Capture honeypot traffic:
```bash
cd /home/fenix/projects/agentic-nids/agent

# List interfaces
.venv/bin/nfstream-collector list-interfaces

# Find the Docker bridge (br-XXXXX)
# Then capture:
sudo .venv/bin/nfstream-collector \
  --interface br-XXXXX \
  --output ../honeypot_traffic.jsonl
```

## 🛑 Stop the Environment

```bash
docker-compose down       # Stop containers
docker-compose down -v    # Stop and remove volumes
```

## 📋 Useful Commands

```bash
# View all container logs
docker-compose logs -f

# View specific container logs
docker-compose logs -f victim2

# Check container status
docker-compose ps

# Restart a container
docker-compose restart victim1

# Execute command in container
docker exec -it honeypot-victim1 bash

# View PGHoney logs
docker exec honeypot-victim2 cat /var/log/pghoney/pghoney.log

# View Redis honeypot logs
docker exec honeypot-victim3 ls -la /var/log/redis-honeypot/
```

## ⚠️  Security Warning

**DO NOT expose these containers to the internet!**

This is a controlled honeypot environment with:
- ✅ Intentionally vulnerable services
- ✅ Weak passwords
- ✅ Command injection vulnerabilities
- ✅ Fake database services

Use ONLY for:
- Security training
- Attack pattern analysis
- IDS/IPS testing
- Network forensics practice

## 🎓 Learning Paths

1. **Beginner**: Network scanning with nmap
2. **Intermediate**: Web vulnerability exploitation
3. **Advanced**: Multi-stage attacks and MITM
4. **Expert**: Honeypot evasion detection

See [README.md](README.md) for detailed scenarios and documentation.
