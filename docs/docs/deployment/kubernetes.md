---
sidebar_position: 2
---

# Kubernetes Deployment

## Namespace and Secrets

```bash
kubectl create namespace nids

kubectl create secret generic nids-secrets \
  --from-literal=anthropicApiKey=$ANTHROPIC_API_KEY \
  --from-literal=clickhousePassword=strong-password \
  -n nids
```

## ClickHouse (StatefulSet)

```yaml
# k8s/clickhouse.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: clickhouse
  namespace: nids
spec:
  serviceName: clickhouse
  replicas: 1
  selector:
    matchLabels:
      app: clickhouse
  template:
    metadata:
      labels:
        app: clickhouse
    spec:
      containers:
        - name: clickhouse
          image: clickhouse/clickhouse-server:latest
          ports:
            - containerPort: 8123
            - containerPort: 9000
          env:
            - name: CLICKHOUSE_DB
              value: nids
            - name: CLICKHOUSE_USER
              value: nids_agent
            - name: CLICKHOUSE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: nids-secrets
                  key: clickhousePassword
          volumeMounts:
            - name: data
              mountPath: /var/lib/clickhouse
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: [ReadWriteOnce]
        resources:
          requests:
            storage: 50Gi
---
apiVersion: v1
kind: Service
metadata:
  name: clickhouse
  namespace: nids
spec:
  clusterIP: None
  selector:
    app: clickhouse
  ports:
    - name: http
      port: 8123
    - name: native
      port: 9000
```

## NIDS Agent (Deployment)

```yaml
# k8s/nids-agent.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nids-agent
  namespace: nids
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nids-agent
  template:
    metadata:
      labels:
        app: nids-agent
    spec:
      containers:
        - name: nids-agent
          image: ghcr.io/zenforcode/agentic-nids:latest
          env:
            - name: ANTHROPIC_API_KEY
              valueFrom:
                secretKeyRef:
                  name: nids-secrets
                  key: anthropicApiKey
            - name: CLICKHOUSE_HOST
              value: clickhouse.nids.svc.cluster.local
            - name: CLICKHOUSE_DATABASE
              value: nids
            - name: CLICKHOUSE_USERNAME
              value: nids_agent
            - name: CLICKHOUSE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: nids-secrets
                  key: clickhousePassword
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
```

## Apply

```bash
kubectl apply -f k8s/clickhouse.yaml
kubectl apply -f k8s/nids-agent.yaml

kubectl rollout status deployment/nids-agent -n nids
kubectl logs -f deployment/nids-agent -n nids
```

## Helm Chart

```bash
helm install agentic-nids ./infra/helm/agentic-nids \
  --namespace nids \
  --set anthropicApiKey=$ANTHROPIC_API_KEY \
  --set clickhouse.password=strong-password
```
