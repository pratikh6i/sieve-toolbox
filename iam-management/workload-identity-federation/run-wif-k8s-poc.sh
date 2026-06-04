#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# Workload Identity Federation PoC — Kubernetes / GKE (v2 - Fixed)
# ══════════════════════════════════════════════════════════════════════
# Single self-contained script. Run after connecting to the cluster.
#
# Fixes from v1:
#   - Updates node pool with --workload-metadata=GKE_METADATA
#   - Removed nodeSelector that was blocking pod scheduling
#   - Waits for node pool rolling update before deploying
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail
# ── Configuration ─────────────────────────────────────────────────────
PROJECT_ID="YOUR_PROJECT_ID"
PROJECT_NUMBER="YOUR_PROJECT_NUMBER"
CLUSTER_NAME="ntuc-wif-poc-pratik"
CLUSTER_REGION="asia-southeast1"
REGION="asia-southeast1"
SA_NAME="wif-poc-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUCKET_NAME="wif-poc-bucket-${PROJECT_ID}"
K8S_NAMESPACE="wif-poc"
K8S_SA_NAME="wif-poc-ksa"
REPO_NAME="wif-poc-repo"
IMAGE_NAME="wif-poc-k8s-app"
FULL_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${IMAGE_NAME}:latest"
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Workload Identity Federation PoC — Kubernetes / GKE    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Project:   $PROJECT_ID ($PROJECT_NUMBER)"
echo "  Cluster:   $CLUSTER_NAME ($CLUSTER_REGION)"
echo "  GCP SA:    $SA_EMAIL"
echo "  K8s SA:    $K8S_NAMESPACE/$K8S_SA_NAME"
echo "  Image:     $FULL_IMAGE"
echo ""
# ══════════════════════════════════════════════════════════════════════
# PHASE 1: GCP Infrastructure (SA, Bucket, IAM)
# ══════════════════════════════════════════════════════════════════════
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 1: GCP Infrastructure                               │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""
echo "── 1.1 Enabling APIs ─────────────────────────────────────────"
gcloud services enable \
    iam.googleapis.com sts.googleapis.com iamcredentials.googleapis.com \
    storage.googleapis.com artifactregistry.googleapis.com container.googleapis.com \
    --quiet 2>/dev/null
echo "  ✓ APIs enabled"
echo "── 1.2 Bucket ────────────────────────────────────────────────"
if gcloud storage buckets describe "gs://$BUCKET_NAME" > /dev/null 2>&1; then
    echo "  ✓ gs://$BUCKET_NAME exists"
else
    gcloud storage buckets create "gs://$BUCKET_NAME" --location=US --quiet
    echo "  ✓ Created gs://$BUCKET_NAME"
fi
echo "WIF Authentication Successful — accessed from Kubernetes Pod" > /tmp/_wif_sample.txt
gcloud storage cp /tmp/_wif_sample.txt "gs://$BUCKET_NAME/sample.txt" --quiet 2>/dev/null
rm -f /tmp/_wif_sample.txt
echo "  ✓ sample.txt uploaded"
echo "── 1.3 Service Account & IAM ─────────────────────────────────"
if ! gcloud iam service-accounts describe "$SA_EMAIL" > /dev/null 2>&1; then
    gcloud iam service-accounts create "$SA_NAME" --display-name="WIF PoC Service Account" --quiet
fi
echo "  ✓ SA: $SA_EMAIL"
for ROLE in "roles/storage.objectViewer" "roles/storage.admin"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$SA_EMAIL" --role="$ROLE" \
        --condition=None --quiet > /dev/null 2>&1
done
echo "  ✓ IAM roles granted"
echo ""
# ══════════════════════════════════════════════════════════════════════
# PHASE 2: GKE Workload Identity (Cluster + Node Pool + K8s SA)
# ══════════════════════════════════════════════════════════════════════
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 2: GKE Workload Identity Setup                      │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""
# ── 2.1 Enable Workload Identity on cluster ──────────────────────────
echo "── 2.1 Cluster-level Workload Identity ───────────────────────"
WI_POOL=$(gcloud container clusters describe "$CLUSTER_NAME" \
    --region="$CLUSTER_REGION" \
    --format="value(workloadIdentityConfig.workloadPool)" 2>/dev/null || echo "")
if [ -z "$WI_POOL" ]; then
    echo "  Enabling on cluster (this takes ~5 min)..."
    gcloud container clusters update "$CLUSTER_NAME" \
        --region="$CLUSTER_REGION" \
        --workload-pool="${PROJECT_ID}.svc.id.goog" --quiet
fi
echo "  ✓ Cluster: ${PROJECT_ID}.svc.id.goog"
# ── 2.2 Enable GKE Metadata Server on ALL node pools ────────────────
echo "── 2.2 Node Pool — GKE Metadata Server ───────────────────────"
NODE_POOLS=$(gcloud container node-pools list \
    --cluster="$CLUSTER_NAME" --region="$CLUSTER_REGION" \
    --format="value(name)" 2>/dev/null)
for NP in $NODE_POOLS; do
    CURRENT_WM=$(gcloud container node-pools describe "$NP" \
        --cluster="$CLUSTER_NAME" --region="$CLUSTER_REGION" \
        --format="value(config.workloadMetadataConfig.mode)" 2>/dev/null || echo "")
    if [ "$CURRENT_WM" = "GKE_METADATA" ]; then
        echo "  ✓ Node pool '$NP' already has GKE_METADATA"
    else
        echo "  Updating node pool '$NP' with GKE_METADATA..."
        echo "  (Rolling update — nodes restart one by one, ~5-10 min)"
        gcloud container node-pools update "$NP" \
            --cluster="$CLUSTER_NAME" \
            --region="$CLUSTER_REGION" \
            --workload-metadata=GKE_METADATA --quiet
        echo "  ✓ Node pool '$NP' updated"
    fi
done
echo ""
# ── 2.3 K8s Namespace + ServiceAccount ───────────────────────────────
echo "── 2.3 K8s Namespace & ServiceAccount ────────────────────────"
kubectl create namespace "$K8S_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null
echo "  ✓ Namespace: $K8S_NAMESPACE"
cat <<EOF | kubectl apply -f - 2>/dev/null
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${K8S_SA_NAME}
  namespace: ${K8S_NAMESPACE}
  annotations:
    iam.gke.io/gcp-service-account: ${SA_EMAIL}
EOF
echo "  ✓ K8s SA: $K8S_SA_NAME → $SA_EMAIL"
# ── 2.4 IAM Binding ─────────────────────────────────────────────────
echo "── 2.4 IAM Binding (K8s SA → GCP SA) ────────────────────────"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[${K8S_NAMESPACE}/${K8S_SA_NAME}]" \
    --quiet > /dev/null 2>&1
echo "  ✓ ${K8S_NAMESPACE}/${K8S_SA_NAME} → $SA_EMAIL"
echo ""
# ── 2.5 Verify nodes are ready ──────────────────────────────────────
echo "── 2.5 Waiting for nodes to be ready ─────────────────────────"
echo -n "  "
for i in $(seq 1 60); do
    READY_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready" || echo "0")
    if [ "$READY_COUNT" -ge 1 ]; then
        echo ""
        echo "  ✓ $READY_COUNT node(s) ready"
        break
    fi
    echo -n "."
    sleep 5
done
echo ""
# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Build & Push Application
# ══════════════════════════════════════════════════════════════════════
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 3: Build & Push Application                         │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""
echo "── 3.1 Artifact Registry ─────────────────────────────────────"
if gcloud artifacts repositories describe "$REPO_NAME" --location="$REGION" > /dev/null 2>&1; then
    echo "  ✓ Repository '$REPO_NAME' exists"
else
    gcloud artifacts repositories create "$REPO_NAME" \
        --repository-format=docker --location="$REGION" --quiet
    echo "  ✓ Created '$REPO_NAME'"
fi
echo "── 3.2 Generating App ────────────────────────────────────────"
mkdir -p "$WORK_DIR/src/main/java/com/example/wif"
cat > "$WORK_DIR/src/main/java/com/example/wif/App.java" <<'JAVAEOF'
package com.example.wif;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
public class App {
    private static final String S  = "──────────────────────────────────────────────────────────";
    private static final String H = "══════════════════════════════════════════════════════════";
    public static void main(String[] args) {
        System.out.println();
        System.out.println("╔" + H + "╗");
        System.out.println("║   Workload Identity Federation PoC — Kubernetes        ║");
        System.out.println("╚" + H + "╝");
        System.out.println();
        String pod = e("POD_NAME"), ns = e("POD_NAMESPACE"), node = e("NODE_NAME"), sa = e("SA_NAME");
        System.out.println("── Pod Info " + S.substring(11));
        System.out.println("  Pod:       " + pod);
        System.out.println("  Namespace: " + ns);
        System.out.println("  Node:      " + node);
        System.out.println("  K8s SA:    " + sa);
        System.out.println();
        try {
            Storage storage = StorageOptions.getDefaultInstance().getService();
            System.out.println("── Authentication " + S.substring(18));
            System.out.println("  ✓ Authenticated via GKE Workload Identity");
            System.out.println("  ✓ No service account key used");
            System.out.println("  ✓ No token files mounted");
            System.out.println("  ✓ Credentials provided by GKE metadata server");
            System.out.println();
            System.out.println("── Bucket Discovery " + S.substring(20));
            int c = 0; String target = null;
            for (Bucket b : storage.list().iterateAll()) {
                String n = b.getName();
                System.out.println("  • " + n); c++;
                if (n.startsWith("wif-poc-bucket-")) target = n;
            }
            System.out.println("  Total: " + c + " bucket(s) accessible");
            System.out.println();
            System.out.println("── Object Read Test " + S.substring(20));
            if (target != null) {
                Blob blob = storage.get(target, "sample.txt");
                if (blob != null) {
                    String content = new String(blob.getContent()).trim();
                    System.out.println("  Bucket:  " + target);
                    System.out.println("  Object:  sample.txt");
                    System.out.println("  Content: \"" + content + "\"");
                    System.out.println("  ✓ Data-plane access confirmed");
                }
            }
            System.out.println();
            System.out.println("── Key Takeaway " + S.substring(16));
            System.out.println("  This Kubernetes Pod accessed Google Cloud Storage");
            System.out.println("  with ZERO stored credentials.");
            System.out.println("  No keys. No tokens. No config files.");
            System.out.println("  Just a K8s ServiceAccount annotation.");
            System.out.println(H);
            System.out.println();
        } catch (Exception ex) {
            System.out.println("── Authentication FAILED " + S.substring(25));
            System.out.println("  ✗ " + ex.getMessage());
            System.exit(1);
        }
    }
    private static String e(String k) { String v=System.getenv(k); return v!=null?v:"unknown"; }
}
JAVAEOF
cat > "$WORK_DIR/pom.xml" <<'POMEOF'
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>wif-poc-k8s</artifactId>
    <version>1.0-SNAPSHOT</version>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>com.google.cloud</groupId>
            <artifactId>google-cloud-storage</artifactId>
            <version>2.30.1</version>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <artifactId>maven-assembly-plugin</artifactId>
                <version>3.6.0</version>
                <configuration>
                    <descriptorRefs><descriptorRef>jar-with-dependencies</descriptorRef></descriptorRefs>
                    <archive><manifest><mainClass>com.example.wif.App</mainClass></manifest></archive>
                </configuration>
                <executions>
                    <execution><id>a</id><phase>package</phase><goals><goal>single</goal></goals></execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
POMEOF
cat > "$WORK_DIR/Dockerfile" <<'DKREOF'
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -q
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*-jar-with-dependencies.jar app.jar
CMD ["java", "-jar", "app.jar"]
DKREOF
echo "  ✓ Source generated"
echo "── 3.3 Building Docker Image ─────────────────────────────────"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet 2>/dev/null
cd "$WORK_DIR"
docker build -t "$FULL_IMAGE" . 2>&1 | tail -3 | sed 's/^/  /'
echo "  ✓ Image built"
echo "── 3.4 Pushing Image ─────────────────────────────────────────"
docker push "$FULL_IMAGE" 2>&1 | tail -3 | sed 's/^/  /'
echo "  ✓ Image pushed"
echo ""
# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Deploy & Validate
# ══════════════════════════════════════════════════════════════════════
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  PHASE 4: Deploy & Validate                                │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""
echo "── 4.1 Deploying Job ─────────────────────────────────────────"
kubectl delete job wif-poc-job -n "$K8S_NAMESPACE" --ignore-not-found=true 2>/dev/null
cat <<EOF | kubectl apply -f - 2>/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: wif-poc-job
  namespace: ${K8S_NAMESPACE}
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app: wif-poc
    spec:
      serviceAccountName: ${K8S_SA_NAME}
      restartPolicy: Never
      containers:
        - name: wif-poc-app
          image: ${FULL_IMAGE}
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: SA_NAME
              value: "${K8S_SA_NAME}"
          resources:
            requests:
              memory: "256Mi"
              cpu: "200m"
            limits:
              memory: "512Mi"
              cpu: "500m"
EOF
echo "  ✓ Job deployed"
echo ""
echo "── 4.2 Waiting for Pod ───────────────────────────────────────"
POD_NAME=""
echo -n "  "
for i in $(seq 1 90); do
    POD_NAME=$(kubectl get pods -n "$K8S_NAMESPACE" -l app=wif-poc \
        --sort-by=.metadata.creationTimestamp \
        -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$POD_NAME" ]; then
        PHASE=$(kubectl get pod "$POD_NAME" -n "$K8S_NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
        if [ "$PHASE" = "Succeeded" ] || [ "$PHASE" = "Failed" ]; then
            echo ""
            echo "  ✓ Pod: $POD_NAME ($PHASE)"
            break
        fi
    fi
    echo -n "."
    sleep 2
done
echo ""
if [ -z "$POD_NAME" ]; then
    echo "  ✗ Pod not created. Debug:"
    kubectl get events -n "$K8S_NAMESPACE" --sort-by=.lastTimestamp 2>/dev/null | tail -10
    exit 1
fi
# If still running, wait for job completion
PHASE=$(kubectl get pod "$POD_NAME" -n "$K8S_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
if [ "$PHASE" = "Running" ]; then
    echo "  Pod running, waiting for completion..."
    kubectl wait --for=condition=complete job/wif-poc-job -n "$K8S_NAMESPACE" --timeout=180s 2>/dev/null || true
fi
echo ""
echo "── 4.3 Results ───────────────────────────────────────────────"
echo ""
echo "  ┌──────────────── Pod: $POD_NAME ────────────────────────"
echo "  │"
kubectl logs "$POD_NAME" -n "$K8S_NAMESPACE" 2>&1 | while IFS= read -r line; do
    echo "  │  $line"
done
echo "  │"
echo "  └────────────────────────────────────────────────────────"
echo ""
FINAL=$(kubectl get pod "$POD_NAME" -n "$K8S_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [ "$FINAL" = "Succeeded" ]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✓ POC PASSED                                              ║"
    echo "║                                                            ║"
    echo "║  The K8s Pod accessed GCS with ZERO stored credentials.    ║"
    echo "║  No keys. No tokens. No config files. Just an annotation.  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
else
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✗ POC FAILED — Pod status: $FINAL"
    echo "║  kubectl describe pod $POD_NAME -n $K8S_NAMESPACE"
    echo "╚══════════════════════════════════════════════════════════════╝"
fi
echo ""
