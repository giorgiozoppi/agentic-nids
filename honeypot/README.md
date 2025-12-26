# Honeypot Network Environment

A Docker-based honeypot network for security testing and intrusion detection training.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Honeypot Network (172.20.0.0/24)               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Attacker    │  │   Victim 1   │  │   Victim 2   │     │
│  │ 172.20.0.10  │  │ 172.20.0.20  │  │ 172.20.0.30  │     │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤     │
│  │ • Kali Linux │  │ • Apache     │  │ • Nginx      │     │
│  │ • nmap       │  │ • vsftpd     │  │ • vsftpd     │     │
│  │ • ettercap   │  │ • Postfix    │  │ • Postfix    │     │
│  │ • Metasploit │  │ • SSH        │  │ • pghoney    │     │
│  │ • sqlmap     │  │ • Weak       │  │ • SSH        │     │
│  │ • hydra      │  │   passwords  │  │ • Weak       │     │
│  │ • nikto      │  │              │  │   passwords  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Attacker Container
**IP:** 172.20.0.10
**Access:** `ssh root@localhost -p 2201` (password: `attacker123`)

**Tools Installed:**
- **Network Scanning:** nmap, masscan
- **MITM Attacks:** ettercap
- **Exploitation:** metasploit-framework
- **Web Testing:** nikto, wpscan, dirb, gobuster, sqlmap
- **Password Attacks:** hydra, john, hashcat
- **Enumeration:** enum4linux, dnsrecon, dnsenum, whatweb
- **Network Tools:** tcpdump, tshark, netcat, socat

### Victim 1 - Traditional Services
**IP:** 172.20.0.20
**Services:**
- **SSH** (port 22) - `ssh root@localhost -p 2202` (password: `victim123`)
- **HTTP** (port 80) - http://localhost:8081 (Apache with vulnerable PHP)
- **FTP** (port 21) - `ftp localhost -p 2121` (user: ftpuser, pass: ftp123)
- **SMTP** (port 25) - localhost:2525 (Postfix)

**Weak Accounts:**
- root:victim123
- admin:admin
- webmaster:password123
- ftpuser:ftp123
- mailuser:mail123

### Victim 2 - Database Honeypot
**IP:** 172.20.0.30
**Services:**
- **SSH** (port 22) - `ssh root@localhost -p 2203` (password: `victim456`)
- **HTTP** (port 80) - http://localhost:8082 (Nginx with PHP)
- **FTP** (port 21) - `ftp localhost -p 2122` (user: ftpuser, pass: ftp456)
- **SMTP** (port 25) - localhost:2526 (Postfix)
- **PostgreSQL Honeypot** (port 5432) - localhost:5433 ([pghoney](https://github.com/betheroot/pghoney))

**Weak Accounts:**
- root:victim456
- postgres:postgres
- dbadmin:dbadmin123
- webuser:web123
- ftpuser:ftp456

**Honeypot Logs:**
- PostgreSQL interactions: `/var/log/pghoney/pghoney.log`

## Quick Start

### 1. Build and Start

```bash
cd honeypot
docker-compose up -d --build
```

### 2. Check Status

```bash
docker-compose ps
```

### 3. Access Containers

**Attacker:**
```bash
# SSH to attacker
ssh root@localhost -p 2201
# Password: attacker123

# Or use docker exec
docker exec -it honeypot-attacker /bin/bash
```

**Victim 1:**
```bash
ssh root@localhost -p 2202
# Password: victim123
```

**Victim 2:**
```bash
ssh root@localhost -p 2203
# Password: victim456
```

### 4. View Logs

```bash
# View all logs
docker-compose logs -f

# View specific container
docker-compose logs -f victim2

# View PGHoney logs
docker exec honeypot-victim2 tail -f /var/log/pghoney/pghoney.log
```

## Usage Scenarios

### Scenario 1: Network Scanning

From the attacker container:

```bash
# SSH into attacker
ssh root@localhost -p 2201

# Scan the network
nmap -sV 172.20.0.0/24

# Detailed scan of victim1
nmap -sV -sC -p- 172.20.0.20

# Quick scan of all victims
nmap -sT 172.20.0.20 172.20.0.30
```

### Scenario 2: Web Application Testing

```bash
# From attacker container:

# Scan web server
nikto -h http://172.20.0.20

# Directory bruteforce
dirb http://172.20.0.20

# SQL injection testing
sqlmap -u "http://172.20.0.20/index.php?cmd=test"

# Test from host machine:
curl http://localhost:8081
curl "http://localhost:8081/index.php?cmd=whoami"
```

### Scenario 3: Password Attacks

```bash
# From attacker container:

# FTP brute force
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://172.20.0.20

# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://172.20.0.20
```

### Scenario 4: PostgreSQL Honeypot Testing

```bash
# From attacker:
psql -h 172.20.0.30 -U postgres -d honeypot

# From host machine:
psql -h localhost -p 5433 -U postgres -d honeypot
# Password: postgres

# All interactions are logged by pghoney
```

### Scenario 5: MITM Attacks

```bash
# From attacker container:
ettercap -T -M arp:remote /172.20.0.20// /172.20.0.30//
```

## Monitoring with NFStream

You can capture and analyze the honeypot traffic using the NFStream collector:

```bash
# From the host machine (in the agent directory)
sudo .venv/bin/nfstream-collector --interface docker0 --output honeypot_flows.jsonl

# Or specify the honeypot network interface
.venv/bin/nfstream-collector list-interfaces  # Find the bridge interface
sudo .venv/bin/nfstream-collector --interface br-XXXXX --output honeypot_flows.jsonl
```

The collector will capture all network flows between the containers, allowing you to:
- Detect attack patterns
- Analyze traffic behavior
- Identify malicious activities
- Train ML models on labeled attack data

## Security Notes

⚠️ **WARNING:** This is a honeypot environment designed for TESTING ONLY!

- **NEVER** expose these containers to the internet
- **NEVER** use these passwords in production
- All services are intentionally vulnerable
- Use only in isolated lab environments
- Perfect for:
  - Security training
  - IDS/IPS testing
  - Network forensics practice
  - Attack pattern analysis

## Network Isolation

The honeypot network is isolated on `172.20.0.0/24`. To ensure proper isolation:

```bash
# Check network isolation
docker network inspect honeypot_honeypot_net

# The network should NOT have internet access by default
# If needed, you can disable internet access:
docker network create --internal honeypot_isolated
```

## Cleanup

```bash
# Stop all containers
docker-compose down

# Remove containers and volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## File Structure

```
honeypot/
├── docker-compose.yml
├── README.md
├── attacker/
│   └── Dockerfile
├── victim1/
│   └── Dockerfile
├── victim2/
│   └── Dockerfile
└── shared/              # Shared volume between containers
```

## Troubleshooting

### Containers not starting
```bash
docker-compose logs
docker-compose ps
```

### SSH connection refused
```bash
# Check if SSH service is running
docker exec honeypot-victim1 service ssh status
```

### Can't access web services
```bash
# Check if services are running
docker exec honeypot-victim1 service apache2 status
docker exec honeypot-victim2 service nginx status
```

### PGHoney not logging
```bash
# Check pghoney process
docker exec honeypot-victim2 ps aux | grep pghoney

# Restart if needed
docker exec honeypot-victim2 pkill -f pghoney
docker exec honeypot-victim2 bash -c "cd /opt/pghoney && python3 pghoney.py &"
```

## Learning Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NFStream Documentation](https://www.nfstream.org/)

## License

This honeypot environment is for educational purposes only.
