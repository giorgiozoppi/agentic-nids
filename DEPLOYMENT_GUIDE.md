# Agentic NIDS Deployment Guide

## Quick Start

### Prerequisites

- Docker 24.0+
- Kubernetes 1.28+ (for production)
- Helm 3.12+
- Python 3.11+
- NATS Server 2.10+
- InfluxDB 2.7+

### Local Development Setup

1. **Install Dependencies**
```bash
cd agent
pip install -e ".[all]"
```

2. **Start Infrastructure Services**
```bash
# Start NATS
docker run -d --name nats -p 4222:4222 nats:2.10

# Start InfluxDB
docker run -d --name influxdb \
  -p 8086:8086 \
  -e DOCKER_INFLUXDB_INIT_MODE=setup \
  -e DOCKER_INFLUXDB_INIT_USERNAME=admin \
  -e DOCKER_INFLUXDB_INIT_PASSWORD=password123 \
  -e DOCKER_INFLUXDB_INIT_ORG=nids \
  -e DOCKER_INFLUXDB_INIT_BUCKET=network_security \
  influxdb:2.7
```

3. **Set Environment Variables**
```bash
export OPENAI_API_KEY="sk-your-key-here"
export PAGERDUTY_ROUTING_KEY="R0..." # Optional
export INFLUXDB_TOKEN=$(docker exec influxdb influx auth list --json | jq -r '.[0].token')
```

4. **Run Quick Test**
```bash
cd agent
python main.py --mode test
```

## Production Deployment

### Option 1: Kubernetes with Helm

**1. Prepare Secrets**
```bash
kubectl create namespace nids

kubectl create secret generic agentic-nids-secrets \
  --from-literal=openaiApiKey=$OPENAI_API_KEY \
  --from-literal=pagerdutyRoutingKey=$PAGERDUTY_ROUTING_KEY \
  --from-literal=influxdbToken=$(openssl rand -base64 32) \
  --from-literal=influxdbPassword=$(openssl rand -base64 32) \
  -n nids
```

**2. Install Helm Chart**
```bash
cd infra/helm

helm install agentic-nids ./agentic-nids \
  --namespace nids \
  --create-namespace \
  --set classifier.autoscaling.enabled=true \
  --set influxdb.persistence.enabled=true \
  --set influxdb.persistence.size=50Gi
```

**3. Verify Deployment**
```bash
# Check pods
kubectl get pods -n nids

# Check services
kubectl get svc -n nids

# Check HPA
kubectl get hpa -n nids
```

**4. Access UI**
```bash
# Get LoadBalancer IP
export UI_IP=$(kubectl get svc agentic-nids-ui -n nids -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "Dashboard: http://$UI_IP"
```

### Option 2: Docker Compose

**1. Create docker-compose.yml**
```yaml
version: '3.8'

services:
  nats:
    image: nats:2.10
    ports:
      - "4222:4222"
      - "8222:8222"

  influxdb:
    image: influxdb:2.7
    ports:
      - "8086:8086"
    environment:
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_USERNAME=admin
      - DOCKER_INFLUXDB_INIT_PASSWORD=password123
      - DOCKER_INFLUXDB_INIT_ORG=nids
      - DOCKER_INFLUXDB_INIT_BUCKET=network_security
    volumes:
      - influxdb-data:/var/lib/influxdb2

  classifier:
    build:
      context: .
      dockerfile: infra/docker/Dockerfile.classifier
    ports:
      - "50051:50051"
    environment:
      - NATS_URL=nats://nats:4222
    depends_on:
      - nats

  nids:
    build:
      context: .
      dockerfile: infra/docker/Dockerfile.all-in-one
    environment:
      - NATS_URL=nats://nats:4222
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - PAGERDUTY_ROUTING_KEY=${PAGERDUTY_ROUTING_KEY}
      - INFLUXDB_URL=http://influxdb:8086
    depends_on:
      - nats
      - influxdb
      - classifier

volumes:
  influxdb-data:
```

**2. Start Services**
```bash
docker-compose up -d
```

## Configuration

### Helm Values Override

Create `custom-values.yaml`:
```yaml
classifier:
  replicas: 3
  autoscaling:
    minReplicas: 3
    maxReplicas: 15
    targetCPUUtilizationPercentage: 60

llm:
  enabled: true
  model: gpt-4o-mini

pagerduty:
  enabled: true

influxdb:
  persistence:
    size: 100Gi
    storageClass: fast-ssd
  config:
    retentionDays: 30
```

Apply:
```bash
helm upgrade agentic-nids ./agentic-nids \
  -n nids \
  -f custom-values.yaml
```

### Agent Configuration

**Collector Agent** (`config/ndpi_agent.yaml`):
```yaml
collection_interval: 180  # 3 minutes
batch_size: 100
classifier_agent_url: "grpc://classifier-service:50051"
enable_async_classification: true
max_concurrent_requests: 10
alert_threshold: 0.7
```

## Monitoring

### InfluxDB Dashboards

**1. Access InfluxDB UI**
```bash
kubectl port-forward -n nids svc/agentic-nids-influxdb-service 8086:8086
# Open http://localhost:8086
```

**2. Create Dashboard**

Query for malicious flows (last hour):
```flux
from(bucket: "network_security")
  |> range(start: -1h)
  |> filter(fn: (r) => r["_measurement"] == "flow_classification")
  |> filter(fn: (r) => r["prediction"] == "malicious")
  |> group(columns: ["attack_type"])
  |> count()
```

### Prometheus Metrics (Optional)

**1. Install Prometheus**
```bash
helm install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring \
  --create-namespace
```

**2. Add ServiceMonitor**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: agentic-nids
  namespace: nids
spec:
  selector:
    matchLabels:
      app: classifier-agent
  endpoints:
  - port: metrics
```

## Scaling

### Manual Scaling

**Scale classifier:**
```bash
kubectl scale deployment agentic-nids-classifier \
  --replicas=5 \
  -n nids
```

### Auto-Scaling Configuration

**Edit HPA:**
```bash
kubectl edit hpa agentic-nids-classifier-hpa -n nids
```

Update metrics:
```yaml
metrics:
- type: Resource
  resource:
    name: cpu
    target:
      type: Utilization
      averageUtilization: 60  # Scale at 60% CPU
- type: Resource
  resource:
    name: memory
    target:
      type: Utilization
      averageUtilization: 75
```

## Backup and Recovery

### InfluxDB Backup

```bash
# Backup
kubectl exec -n nids influxdb-0 -- \
  influx backup /tmp/backup

# Download backup
kubectl cp nids/influxdb-0:/tmp/backup ./influxdb-backup

# Restore
kubectl cp ./influxdb-backup nids/influxdb-0:/tmp/restore
kubectl exec -n nids influxdb-0 -- \
  influx restore /tmp/restore
```

### Configuration Backup

```bash
# Export Helm values
helm get values agentic-nids -n nids > backup-values.yaml

# Export secrets
kubectl get secret agentic-nids-secrets -n nids -o yaml > backup-secrets.yaml
```

## Upgrade

### Rolling Update

```bash
# Update images
helm upgrade agentic-nids ./agentic-nids \
  -n nids \
  --set classifier.image=jozoppi/agentic-nids-classifier:v2.0

# Monitor rollout
kubectl rollout status deployment/agentic-nids-classifier -n nids
```

### Rollback

```bash
# Rollback to previous version
helm rollback agentic-nids -n nids

# Rollback to specific revision
helm rollback agentic-nids 3 -n nids
```

## Troubleshooting

### Check Logs

```bash
# Classifier logs
kubectl logs -n nids deployment/agentic-nids-classifier --tail=100 -f

# All pods
kubectl logs -n nids --all-containers=true --tail=50
```

### Debug Pod

```bash
kubectl run -it --rm debug \
  --image=busybox \
  --restart=Never \
  -n nids \
  -- sh

# Inside pod:
nslookup agentic-nids-classifier-service
wget -O- http://influxdb-service:8086/health
```

### Resource Issues

```bash
# Check resource usage
kubectl top pods -n nids

# Check events
kubectl get events -n nids --sort-by='.lastTimestamp'

# Describe problematic pod
kubectl describe pod <pod-name> -n nids
```

## Security Hardening

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: classifier-network-policy
  namespace: nids
spec:
  podSelector:
    matchLabels:
      app: classifier-agent
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: collector-agent
    ports:
    - protocol: TCP
      port: 50051
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: nats
    ports:
    - protocol: TCP
      port: 4222
```

### Pod Security Policy

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: agentic-nids-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  runAsUser:
    rule: 'MustRunAsNonRoot'
  fsGroup:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
```

## Performance Tuning

### Classifier Optimization

```yaml
# values.yaml
classifier:
  resources:
    requests:
      cpu: 2000m
      memory: 4Gi
    limits:
      cpu: 4000m
      memory: 8Gi

  # Node affinity for high-performance nodes
  nodeSelector:
    node-type: compute-optimized

  # Anti-affinity for distribution
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: app
              operator: In
              values:
              - classifier-agent
          topologyKey: kubernetes.io/hostname
```

### InfluxDB Optimization

```yaml
influxdb:
  resources:
    requests:
      cpu: 4000m
      memory: 8Gi
    limits:
      cpu: 8000m
      memory: 16Gi

  persistence:
    size: 500Gi
    storageClass: fast-ssd  # Use SSD for better IOPS

  config:
    retentionDays: 7
    # Compact old data
    compactionEnabled: true
```

## Cost Optimization

### Resource Right-Sizing

Monitor actual usage:
```bash
kubectl top pods -n nids --containers
```

Adjust requests/limits based on usage:
```yaml
classifier:
  resources:
    requests:
      cpu: 1000m  # Reduced from 2000m
      memory: 2Gi  # Reduced from 4Gi
```

### Auto-Scaling Tuning

```yaml
classifier:
  autoscaling:
    minReplicas: 1  # Reduce minimum
    maxReplicas: 8
    targetCPUUtilizationPercentage: 80  # Increase threshold
```

### Spot Instances (Cloud)

```yaml
# Node affinity for spot instances
nodeSelector:
  eks.amazonaws.com/capacityType: SPOT  # AWS EKS
  # or
  cloud.google.com/gke-preemptible: "true"  # GKE
```

## Maintenance

### Regular Tasks

**Daily:**
- Check InfluxDB storage usage
- Review error logs
- Verify HPA scaling

**Weekly:**
- Review malicious flow trends
- Update attack signatures
- Retrain ML model if needed

**Monthly:**
- Backup InfluxDB data
- Update dependencies
- Security patches

### Upgrade Checklist

- [ ] Backup current configuration
- [ ] Backup InfluxDB data
- [ ] Test upgrade in staging
- [ ] Schedule maintenance window
- [ ] Perform upgrade
- [ ] Verify all pods healthy
- [ ] Run integration tests
- [ ] Monitor for 24 hours
- [ ] Document changes

## Support

For issues and questions:
- GitHub Issues: https://github.com/your-org/agentic-nids/issues
- Documentation: See IMPLEMENTATION.md
- Training: See agent/models/train_xgboost_model.py
