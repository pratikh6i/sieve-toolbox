#!/bin/bash
# deploy-prowler-master.sh
# The consolidated, error-free deployment script for Prowler on GKE.

NAMESPACE="prowler"
REGION="us-central1"
IP_NAME="prowler-static-ip"

echo "=========================================="
echo "   DEPLOYING PROWLER (MASTER SCRIPT)      "
echo "=========================================="

# 1. Retrieve Static IP
STATIC_IP=$(gcloud compute addresses describe $IP_NAME --region=$REGION --format='get(address)')
echo "--> Using Static IP: $STATIC_IP"

# 2. Generate Security Keys
echo "--> Generating Security Keys..."
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
PRIVATE_KEY=$(awk 'NF {printf "%s\\n", $0}' private.pem)
PUBLIC_KEY=$(awk 'NF {printf "%s\\n", $0}' public.pem)
rm private.pem public.pem

# 3. Create Namespace & Secrets
echo "--> Creating Namespace and Secrets..."
kubectl create namespace $NAMESPACE
kubectl create secret generic prowler-secrets \
    --namespace=$NAMESPACE \
    --from-literal=postgres-password="prowler-db-password" \
    --from-literal=jwt-private-key="$PRIVATE_KEY" \
    --from-literal=jwt-public-key="$PUBLIC_KEY"

# 4. Generate K8s Manifest
echo "--> Generating K8s Manifests..."
cat <<EOF > prowler-master.yaml
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
  REDIS_HOST: "prowler-redis"
  REDIS_PORT: "6379"
---
# --- POSTGRES DATABASE ---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: prowler-db
  namespace: $NAMESPACE
spec:
  serviceName: "prowler-db"
  replicas: 1
  selector:
    matchLabels:
      app: prowler-db
  template:
    metadata:
      labels:
        app: prowler-db
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_USER
          value: "prowler"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: prowler-secrets
              key: postgres-password
        - name: POSTGRES_DB
          value: "prowler"
        - name: PGDATA
          value: "/var/lib/postgresql/data/pgdata"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: db-data
          mountPath: /var/lib/postgresql/data
          subPath: pgdata
  volumeClaimTemplates:
  - metadata:
      name: db-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: prowler-db
  namespace: $NAMESPACE
spec:
  ports:
  - port: 5432
  selector:
    app: prowler-db
---
# --- REDIS ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prowler-redis
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prowler-redis
  template:
    metadata:
      labels:
        app: prowler-redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: prowler-redis
  namespace: $NAMESPACE
spec:
  ports:
  - port: 6379
  selector:
    app: prowler-redis
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
      - name: migrate
        image: prowlercloud/prowler-api:latest
        args: ["python", "manage.py", "migrate"]
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
---
# --- PROWLER UI ---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prowler-ui
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prowler-ui
      tier: prowler-web
  template:
    metadata:
      labels:
        app: prowler-ui
        tier: prowler-web
    spec:
      containers:
      - name: ui
        image: prowlercloud/prowler-ui:stable
        envFrom:
        - configMapRef:
            name: prowler-config
        ports:
        - containerPort: 3000
---
# --- LOAD BALANCER SERVICE ---
apiVersion: v1
kind: Service
metadata:
  name: prowler-lb
  namespace: $NAMESPACE
spec:
  type: LoadBalancer
  loadBalancerIP: $STATIC_IP
  ports:
  - name: ui
    port: 3000
    targetPort: 3000
    protocol: TCP
  - name: api
    port: 8080
    targetPort: 8080
    protocol: TCP
  selector:
    tier: prowler-web
EOF

# 5. Apply Manifest
echo "--> Applying K8s configuration..."
kubectl apply -f prowler-master.yaml

echo "=========================================="
echo "        DEPLOYMENT SUCCESSFUL!            "
echo "=========================================="
echo "Access Dashboard: http://${STATIC_IP}:3000"
echo "Check pods: kubectl get pods -n prowler -w"
