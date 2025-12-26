#!/bin/bash

echo "=========================================="
echo " Honeypot Environment Startup"
echo "=========================================="
echo ""

# Check if Docker Loki plugin is installed
echo "[1/4] Checking Docker Loki logging plugin..."
if ! docker plugin ls | grep -q loki; then
    echo "Installing Docker Loki plugin..."
    docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions
else
    echo "✓ Loki plugin already installed"
fi

# Create shared directory
echo "[2/4] Creating shared directory..."
mkdir -p shared
chmod 777 shared

# Build and start containers
echo "[3/4] Building and starting containers..."
docker-compose up -d --build

# Wait for services to be ready
echo "[4/4] Waiting for services to start (30 seconds)..."
sleep 30

# Show status
echo ""
echo "=========================================="
echo " Honeypot Environment Status"
echo "=========================================="
docker-compose ps
echo ""

echo "=========================================="
echo " Access Information"
echo "=========================================="
echo ""
echo "🎯 Attacker Container:"
echo "   ssh root@localhost -p 2201 (password: attacker123)"
echo ""
echo "🎯 Victim Servers:"
echo "   Victim 1: ssh root@localhost -p 2202 (password: victim123)"
echo "   Victim 2: ssh root@localhost -p 2203 (password: victim456)"
echo "   Victim 3: ssh root@localhost -p 2204 (password: victim789)"
echo ""
echo "🌐 Web Interfaces:"
echo "   Victim 1 HTTP: http://localhost:8081"
echo "   Victim 2 HTTP: http://localhost:8082"
echo "   Victim 3 HTTP: http://localhost:8083"
echo ""
echo "📊 Monitoring:"
echo "   Grafana: http://localhost:3000 (anonymous access enabled)"
echo "   Loki API: http://localhost:3100"
echo ""
echo "🗃️  Honeypot Services:"
echo "   PostgreSQL (pghoney): localhost:5433"
echo "   Redis (honeypot): localhost:6380"
echo ""
echo "📋 Logs:"
echo "   View all logs: docker-compose logs -f"
echo "   View in Grafana: http://localhost:3000"
echo ""
echo "=========================================="
