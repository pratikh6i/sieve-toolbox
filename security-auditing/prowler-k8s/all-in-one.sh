#!/bin/bash
NAMESPACE="prowler"
REGION="us-central1"
IP_NAME="prowler-static-ip"

echo "=========================================="
echo "    DEPLOYING FINAL BULLETPROOF FIX       "
echo "=========================================="

STATIC_IP=$(gcloud compute addresses describe $IP_NAME --region=$REGION --format='get(address)')

# 1. Wipe the broken deployments
echo "--> Cleaning up old deployments..."
kubectl delete deployment prowler-api prowler-worker prowler-beat -n $NAMESPACE

# 2. Re-create the master configuration
cat << YAML > final-prowler.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prowler-config
  namespace: $NAMESPACE
data:
  AUTH_URL: "http://${STATIC_IP}:3000"
  NEXT_PUBLIC_API_BASE_URL: "http://${STATIC_IP}:8080/api/v1"
  DJANGO_ALLOWED_HOSTS: "localhost,127.0.0.1,prowler-api,${STATIC_IP}"
  POSTGRES_HOST: "prowler-db"
  POSTGRES_PORT: "5432"
  POSTGRES_DB: "prowler"
  POSTGRES_USER: "prowler"
  POSTGRES_ADMIN_USER: "prowler"
  # Valkey replaced Redis in the latest Prowler versions
  VALKEY_HOST: "prowler-redis"
  VALKEY_PORT: "6379"
  REDIS_HOST: "prowler-redis"
  REDIS_PORT: "6379"
  # Keys to satisfy the environ parser
  DJANGO_SECRETS_ENCRYPTION_KEY: "oE/ltOhp/n1TdbHjVmzcjDPLcLA41CVI/4Rk+UB5ESc="
  NEO4J_HOST: "localhost"
  NEO4J_PORT: "7687"
  NEO4J_USER: "neo4j"
  NEO4J_PASSWORD: "dummy-password"
---
# --- PROWLER API ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prowler-api
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prowler-api
      tier: prowler-web
  template:
    metadata:
      labels:
        app: prowler-api
        tier: prowler-web
    spec:
      initContainers:
      - name: wait-for-db
        image: busybox:1.28
        command: ['sh', '-c', "until nc -z prowler-db 5432; do echo waiting for db; sleep 2; done;"]
      
      # Clean Migration: Bypasses the broken entrypoint and uses Poetry directly
      - name: migrate
        image: prowlercloud/prowler-api:latest
        command: ["/bin/sh", "-c"]
        args: 
          - |
            export PATH="/home/prowler/.local/bin:$PATH"
            echo "Running clean migrations..."
            poetry run python manage.py migrate || python manage.py migrate
        envFrom:
        - configMapRef:
            name: prowler-config
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: POSTGRES_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: DJANGO_TOKEN_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-private-key
        - name: DJANGO_TOKEN_VERIFYING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-public-key

      # Main API Container (Uses native entrypoint, so no 'command' override)
      containers:
      - name: api
        image: prowlercloud/prowler-api:latest
        args: ["gunicorn", "-c", "config/guniconf.py", "config.wsgi:application"]
        envFrom:
        - configMapRef:
            name: prowler-config
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: POSTGRES_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: DJANGO_TOKEN_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-private-key
        - name: DJANGO_TOKEN_VERIFYING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-public-key
        ports:
        - containerPort: 8080
---
# --- PROWLER WORKER ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prowler-worker
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prowler-worker
  template:
    metadata:
      labels:
        app: prowler-worker
    spec:
      initContainers:
      - name: wait-for-db
        image: busybox:1.28
        command: ['sh', '-c', "until nc -z prowler-db 5432; do echo waiting for db; sleep 2; done;"]
      containers:
      - name: worker
        image: prowlercloud/prowler-api:latest
        args: ["celery", "-A", "config.celery", "worker", "-l", "info", "-E"]
        envFrom:
        - configMapRef:
            name: prowler-config
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: POSTGRES_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: DJANGO_TOKEN_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-private-key
        - name: DJANGO_TOKEN_VERIFYING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-public-key
---
# --- PROWLER SCHEDULER ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prowler-beat
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prowler-beat
  template:
    metadata:
      labels:
        app: prowler-beat
    spec:
      initContainers:
      - name: wait-for-db
        image: busybox:1.28
        command: ['sh', '-c', "until nc -z prowler-db 5432; do echo waiting for db; sleep 2; done;"]
      containers:
      - name: beat
        image: prowlercloud/prowler-api:latest
        args: ["celery", "-A", "config.celery", "beat", "-l", "info", "--scheduler", "django_celery_beat.schedulers:DatabaseScheduler"]
        envFrom:
        - configMapRef:
            name: prowler-config
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: POSTGRES_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: DJANGO_TOKEN_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-private-key
        - name: DJANGO_TOKEN_VERIFYING_KEY
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: jwt-public-key
YAML

# 3. Apply the fix
echo "--> Applying Final Configuration..."
kubectl apply -f final-prowler.yaml

echo "--> Watching for fresh pods to boot up:"
kubectl get pods -n $NAMESPACE -w
