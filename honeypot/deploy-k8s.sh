#!/bin/bash
set -euo pipefail

NAMESPACE=honeypot
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[$(date +%H:%M:%S)] $*"; }

die() { echo "ERROR: $*" >&2; exit 1; }

command -v microk8s >/dev/null || die "microk8s not found"
command -v docker   >/dev/null || die "docker not found"

echo "=========================================="
echo " Honeypot MicroK8s Deployment"
echo "=========================================="

# ── 1. Enable required addons ──────────────────────────────────────────────
log "Enabling MicroK8s addons (dns, hostpath-storage)..."
microk8s enable dns hostpath-storage 2>/dev/null || true

# ── 2. Build images ────────────────────────────────────────────────────────
log "Building container images..."
docker build -q -t honeypot-attacker:latest "$SCRIPT_DIR/attacker" &
docker build -q -t honeypot-victim1:latest  "$SCRIPT_DIR/victim1"  &
docker build -q -t honeypot-victim2:latest  "$SCRIPT_DIR/victim2"  &
docker build -q -t honeypot-victim3:latest  "$SCRIPT_DIR/victim3"  &
wait
log "All images built."

# ── 3. Import images into MicroK8s containerd ─────────────────────────────
log "Importing images into MicroK8s..."
for img in honeypot-attacker honeypot-victim1 honeypot-victim2 honeypot-victim3; do
    log "  importing $img:latest"
    docker save "$img:latest" | microk8s ctr images import -
done

# ── 4. Apply manifests ─────────────────────────────────────────────────────
log "Applying Kubernetes manifests..."
microk8s kubectl apply -k "$SCRIPT_DIR/k8s/"

# ── 5. Wait for pods ───────────────────────────────────────────────────────
log "Waiting for pods to become ready (up to 5 min)..."
microk8s kubectl wait \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/part-of=honeypot \
    --namespace="$NAMESPACE" \
    --timeout=300s

echo ""
echo "=========================================="
echo " Deployment Status"
echo "=========================================="
microk8s kubectl get pods,svc -n "$NAMESPACE"
echo ""

NODE_IP=$(microk8s kubectl get nodes \
    -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

echo "=========================================="
echo " Access Information  (node: $NODE_IP)"
echo "=========================================="
echo ""
echo "Attacker:"
echo "  ssh root@$NODE_IP -p 2201          (password: attacker123)"
echo "  microk8s kubectl exec -it deploy/attacker -n $NAMESPACE -- bash"
echo ""
echo "Victims:"
echo "  ssh root@$NODE_IP -p 2202          victim1  (password: victim123)"
echo "  ssh root@$NODE_IP -p 2203          victim2  (password: victim456)"
echo "  ssh root@$NODE_IP -p 2204          victim3  (password: victim789)"
echo ""
echo "Web Interfaces:"
echo "  http://$NODE_IP:8081               victim1 (Apache + RCE honeypot)"
echo "  http://$NODE_IP:8082               victim2 (Nginx + DB portal)"
echo "  http://$NODE_IP:8083               victim3 (Lighttpd + Redis info)"
echo ""
echo "Monitoring:"
echo "  http://$NODE_IP:3000               Grafana (anonymous, admin)"
echo "  Loki API (cluster-internal):       http://loki.honeypot.svc:3100"
echo ""
echo "Honeypot Services:"
echo "  $NODE_IP:5433                      PostgreSQL honeypot (pghoney)"
echo "  $NODE_IP:6380                      Redis honeypot"
echo ""
echo "Useful Commands:"
echo "  microk8s kubectl logs -f deploy/victim2 -n $NAMESPACE"
echo "  microk8s kubectl exec -it deploy/attacker -n $NAMESPACE -- nmap victim1"
echo "  microk8s kubectl delete -k k8s/    (tear down)"
echo "=========================================="
