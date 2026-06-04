# Deepfence ThreatMapper Deployment Guide on GCP

This document provides a step-by-step guide for deploying Deepfence ThreatMapper on a Google Cloud Platform (GCP) Virtual Machine (VM) instance. It covers VM creation, firewall rule configuration, Docker/Docker Compose installation, and deployment of the ThreatMapper console.

---

## Prerequisites
*   **GCP Account**: Access to a GCP project with billing enabled.
*   **IAM Roles**:
    *   `Compute Instance Admin` (to create VMs).
    *   `Security Admin` or `Compute Security Admin` (to configure firewalls).
*   **Resource Requirements**: Ensure your selected machine type meets the recommended specifications for the ThreatMapper Console (refer to the official [ThreatMapper requirements documentation](https://community.deepfence.io/threatmapper/docs/console/requirements)).

---

## Deployment Steps

### Step 1: Create a GCP VM Instance
1. In the GCP Console, navigate to **Compute Engine** -> **VM instances**.
2. Click **Create Instance**.
3. Configure the VM parameters:
    *   **Name**: `threatmapper-vm` (or your preferred name).
    *   **Region/Zone**: Select your desired deployment region.
    *   **Machine configuration**: Select a machine type matching ThreatMapper requirements (typically at least 4 vCPUs and 8GB-16GB RAM).
    *   **Boot disk**: Select **Debian GNU/Linux 11 (bullseye)** or newer.
    *   **Firewall**: Check **Allow HTTP traffic** and **Allow HTTPS traffic** (ThreatMapper console uses HTTP/HTTPS for UI access).
    *   **Network tags**: Add a specific tag (e.g., `ssh-allow-threatmapper`) to apply firewall rules.
4. Click **Create** to launch the instance.

### Step 2: Configure Firewall for SSH Access
1. Navigate to **VPC network** -> **Firewalls** in the GCP Console.
2. Click **Create Firewall Rule**.
3. Set the following parameters:
    *   **Name**: `ssh-allow-threatmapper`
    *   **Network**: `default` (or your target VPC network)
    *   **Direction**: `Ingress`
    *   **Action**: `Allow`
    *   **Targets**: `Specified target tags`
    *   **Target tags**: `ssh-allow-threatmapper`
    *   **Source filter**: `IP ranges`
    *   **Source IP ranges**: Enter your public IP address (e.g., `YOUR_PUBLIC_IP/32`) to restrict SSH access securely.
    *   **Protocols and ports**: Select **Specified protocols and ports** -> check **TCP** and enter `22`.
4. Click **Create**.

### Step 3: Connect via SSH
Connect to your VM instance using the GCP console SSH interface or the `gcloud` CLI:
```bash
gcloud compute ssh threatmapper-vm --zone=YOUR_VM_ZONE
```

### Step 4: Install Docker
Run the following commands on the VM to install the official Docker Engine:
```bash
# Add Docker's official GPG key
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker packages
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Step 5: Install Docker Compose (V1 Compatibility Helper)
Download and configure the standalone `docker-compose` binary:
```bash
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker-compose --version
```

### Step 6: Download ThreatMapper Compose File
Download the official `docker-compose.yml` configuration:
```bash
wget https://github.com/deepfence/ThreatMapper/raw/release-2.4/deployment-scripts/docker-compose.yml
```

### Step 7: Deploy ThreatMapper Console
Start the containers in detached daemon mode:
```bash
docker compose up -d
```
All ThreatMapper backend services, UI, and databases will launch shortly. You can monitor progress with `docker compose ps` and access the dashboard by navigating to the VM's public IP address in your browser.
