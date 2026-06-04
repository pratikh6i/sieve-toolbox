#!/usr/bin/env python3
"""
GCP Security Health Analytics Scanner
=====================================
A comprehensive security scanner for GCP resources that generates findings
compatible with Google Security Command Center (SCC) format.

This scanner performs READ-ONLY operations and does NOT modify any infrastructure.
It uses only metadata APIs to avoid incurring costs from object reads.

Supported Resources:
- Compute Engine Instances
- GKE Clusters
- Cloud Storage Buckets
- VPC Firewall Rules
- Cloud SQL Instances

Usage:
    python gcp_security_scanner.py --org-id <ORG_ID>
    python gcp_security_scanner.py --project-ids project1,project2,project3

Author: Security Automation Team
License: MIT
"""

import argparse
import csv
import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import time

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")

# Progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# GCP Libraries
try:
    from google.cloud import compute_v1
    from google.cloud import container_v1
    from google.cloud import storage
    from google.cloud import resourcemanager_v3
    from google.api_core import exceptions as google_exceptions
    from googleapiclient import discovery
    from google.auth import default as google_auth_default
    GCP_LIBS_AVAILABLE = True
except ImportError as e:
    GCP_LIBS_AVAILABLE = False
    print("ERROR: Required GCP libraries not installed.")
    print("Run: pip install google-cloud-compute google-cloud-container google-cloud-storage google-cloud-resource-manager google-api-python-client")
    print(f"Import error: {e}")
    sys.exit(1)


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class Severity(Enum):
    """SCC-compatible severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingState(Enum):
    """Finding states"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class FindingClass(Enum):
    """SCC finding classes"""
    VULNERABILITY = "VULNERABILITY"
    MISCONFIGURATION = "MISCONFIGURATION"
    OBSERVATION = "OBSERVATION"


@dataclass
class Finding:
    """SCC-compatible finding structure"""
    name: str  # Unique finding ID
    category: str  # e.g., FULL_API_ACCESS
    severity: Severity
    state: FindingState
    finding_class: FindingClass
    resource_name: str  # Full resource path
    resource_type: str  # e.g., compute.googleapis.com/Instance
    resource_project: str
    resource_location: str
    description: str
    remediation: str
    compliance: List[str] = field(default_factory=list)
    scan_time: str = ""
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for CSV export"""
        return {
            "finding_name": self.name,
            "finding_category": self.category,
            "finding_severity": self.severity.value,
            "finding_state": self.state.value,
            "finding_class": self.finding_class.value,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "resource_project": self.resource_project,
            "resource_location": self.resource_location,
            "finding_description": self.description,
            "remediation": self.remediation,
            "compliance": "; ".join(self.compliance),
            "scan_time": self.scan_time or datetime.utcnow().isoformat() + "Z"
        }


# =============================================================================
# FINDING DEFINITIONS (SCC-ALIGNED)
# =============================================================================

FINDING_DEFINITIONS = {
    # =========================================================================
    # COMPUTE INSTANCE FINDINGS
    # =========================================================================
    "FULL_API_ACCESS": {
        "severity": Severity.CRITICAL,
        "description": "Compute instance has full access to all Cloud APIs via cloud-platform scope",
        "remediation": "Restrict API access scopes to only required APIs. Avoid using cloud-platform scope.",
        "compliance": ["CIS GCP 4.2", "NIST 800-53 AC-6"]
    },
    "PUBLIC_IP_ADDRESS": {
        "severity": Severity.HIGH,
        "description": "Compute instance has an external (public) IP address assigned",
        "remediation": "Remove external IP if not required. Use Cloud NAT for outbound access.",
        "compliance": ["CIS GCP 4.9", "NIST 800-53 SC-7"]
    },
    "COMPUTE_SECURE_BOOT_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Shielded VM Secure Boot is not enabled on this instance",
        "remediation": "Enable Secure Boot in Shielded VM settings to protect against boot-level malware.",
        "compliance": ["CIS GCP 4.8", "NIST 800-53 SI-7"]
    },
    "CONFIDENTIAL_COMPUTING_DISABLED": {
        "severity": Severity.LOW,
        "description": "Confidential Computing is disabled on this N2D instance",
        "remediation": "Enable Confidential VM for sensitive workloads to encrypt data in use.",
        "compliance": ["CIS GCP 4.11", "NIST 800-53 SC-28"]
    },
    "IP_FORWARDING_ENABLED": {
        "severity": Severity.MEDIUM,
        "description": "IP forwarding is enabled, allowing the instance to route traffic",
        "remediation": "Disable IP forwarding unless the instance is acting as a NAT gateway or router.",
        "compliance": ["CIS GCP 4.6", "NIST 800-53 SC-7"]
    },
    "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED": {
        "severity": Severity.MEDIUM,
        "description": "Instance allows project-wide SSH keys, enabling login from any project key",
        "remediation": "Block project-wide SSH keys and use instance-specific keys instead.",
        "compliance": ["CIS GCP 4.3", "NIST 800-53 AC-17"]
    },
    "DEFAULT_SERVICE_ACCOUNT_USED": {
        "severity": Severity.MEDIUM,
        "description": "Instance uses the default Compute Engine service account",
        "remediation": "Create and use a custom service account with minimal required permissions.",
        "compliance": ["CIS GCP 4.1", "NIST 800-53 AC-6"]
    },
    "OS_LOGIN_DISABLED": {
        "severity": Severity.LOW,
        "description": "OS Login is not enabled for centralized SSH key management",
        "remediation": "Enable OS Login for IAM-based SSH access control.",
        "compliance": ["CIS GCP 4.4", "NIST 800-53 IA-2"]
    },
    "SERIAL_PORT_ENABLED": {
        "severity": Severity.MEDIUM,
        "description": "Serial port access is enabled on this instance",
        "remediation": "Disable serial port access to reduce attack surface.",
        "compliance": ["CIS GCP 4.5", "NIST 800-53 AC-3"]
    },
    "INTEGRITY_MONITORING_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Shielded VM integrity monitoring is disabled",
        "remediation": "Enable integrity monitoring to detect boot-level tampering.",
        "compliance": ["CIS GCP 4.8", "NIST 800-53 SI-7"]
    },
    "VTPM_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Virtual TPM (vTPM) is disabled on this Shielded VM",
        "remediation": "Enable vTPM for measured boot and attestation.",
        "compliance": ["CIS GCP 4.8", "NIST 800-53 SI-7"]
    },
    "DELETION_PROTECTION_DISABLED": {
        "severity": Severity.LOW,
        "description": "Deletion protection is not enabled on this instance",
        "remediation": "Enable deletion protection to prevent accidental deletion of critical instances.",
        "compliance": ["NIST 800-53 CP-9"]
    },
    
    # =========================================================================
    # GKE CLUSTER FINDINGS
    # =========================================================================
    "PRIVATE_CLUSTER_DISABLED": {
        "severity": Severity.HIGH,
        "description": "GKE cluster has a public endpoint (not a private cluster)",
        "remediation": "Create a private cluster with private nodes to limit exposure.",
        "compliance": ["CIS GKE 6.6.2", "NIST 800-53 SC-7"]
    },
    "MASTER_AUTHORIZED_NETWORKS_DISABLED": {
        "severity": Severity.HIGH,
        "description": "Master authorized networks are not configured",
        "remediation": "Enable master authorized networks to restrict API server access.",
        "compliance": ["CIS GKE 6.6.3", "NIST 800-53 AC-3"]
    },
    "CLUSTER_SHIELDED_NODES_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Shielded GKE nodes are not enabled",
        "remediation": "Enable Shielded GKE Nodes for node integrity verification.",
        "compliance": ["CIS GKE 6.5.5", "NIST 800-53 SI-7"]
    },
    "WORKLOAD_IDENTITY_DISABLED": {
        "severity": Severity.HIGH,
        "description": "Workload Identity is not enabled, pods use node service account",
        "remediation": "Enable Workload Identity for fine-grained pod IAM access.",
        "compliance": ["CIS GKE 6.2.2", "NIST 800-53 AC-6"]
    },
    "LEGACY_AUTHORIZATION_ENABLED": {
        "severity": Severity.HIGH,
        "description": "Legacy ABAC authorization is enabled instead of RBAC",
        "remediation": "Disable legacy authorization and use RBAC.",
        "compliance": ["CIS GKE 6.8.4", "NIST 800-53 AC-3"]
    },
    "CLUSTER_LOGGING_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Cluster logging is not enabled",
        "remediation": "Enable Cloud Logging for cluster audit and monitoring.",
        "compliance": ["CIS GKE 6.7.1", "NIST 800-53 AU-2"]
    },
    "CLUSTER_MONITORING_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Cluster monitoring is not enabled",
        "remediation": "Enable Cloud Monitoring for cluster health visibility.",
        "compliance": ["CIS GKE 6.7.1", "NIST 800-53 SI-4"]
    },
    "NETWORK_POLICY_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Network policy enforcement is not enabled",
        "remediation": "Enable network policy to control pod-to-pod traffic.",
        "compliance": ["CIS GKE 6.6.7", "NIST 800-53 SC-7"]
    },
    "AUTO_REPAIR_DISABLED": {
        "severity": Severity.LOW,
        "description": "Node auto-repair is disabled",
        "remediation": "Enable auto-repair to automatically fix unhealthy nodes.",
        "compliance": ["CIS GKE 6.5.2", "NIST 800-53 CP-10"]
    },
    "AUTO_UPGRADE_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Node auto-upgrade is disabled",
        "remediation": "Enable auto-upgrade to receive security patches automatically.",
        "compliance": ["CIS GKE 6.5.3", "NIST 800-53 SI-2"]
    },
    "BINARY_AUTHORIZATION_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Binary Authorization is not enabled",
        "remediation": "Enable Binary Authorization to ensure only trusted images are deployed.",
        "compliance": ["NIST 800-53 CM-7"]
    },
    "ALPHA_CLUSTER_ENABLED": {
        "severity": Severity.HIGH,
        "description": "Alpha cluster features are enabled (not production-ready)",
        "remediation": "Do not use alpha clusters in production environments.",
        "compliance": ["CIS GKE 6.10.2"]
    },
    
    # =========================================================================
    # STORAGE BUCKET FINDINGS
    # =========================================================================
    "PUBLIC_BUCKET_ACL": {
        "severity": Severity.CRITICAL,
        "description": "Cloud Storage bucket is publicly accessible",
        "remediation": "Remove allUsers and allAuthenticatedUsers from bucket IAM policy.",
        "compliance": ["CIS GCP 5.1", "NIST 800-53 AC-3", "PCI-DSS 7.1"]
    },
    "BUCKET_POLICY_ONLY_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Uniform bucket-level access is not enabled",
        "remediation": "Enable uniform bucket-level access to use IAM exclusively.",
        "compliance": ["CIS GCP 5.2", "NIST 800-53 AC-6"]
    },
    "BUCKET_LOGGING_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Access logging is not enabled for this bucket",
        "remediation": "Enable access logging to track bucket access patterns.",
        "compliance": ["CIS GCP 5.3", "NIST 800-53 AU-2"]
    },
    "OBJECT_VERSIONING_DISABLED": {
        "severity": Severity.LOW,
        "description": "Object versioning is not enabled",
        "remediation": "Enable versioning to protect against accidental deletion/overwrite.",
        "compliance": ["NIST 800-53 CP-9"]
    },
    "BUCKET_RETENTION_POLICY_NOT_LOCKED": {
        "severity": Severity.LOW,
        "description": "Bucket has retention policy but it is not locked",
        "remediation": "Lock retention policy to prevent unauthorized changes.",
        "compliance": ["NIST 800-53 AU-11"]
    },
    "PUBLIC_ACCESS_PREVENTION_DISABLED": {
        "severity": Severity.HIGH,
        "description": "Public access prevention is not enforced on this bucket",
        "remediation": "Enable public access prevention to block public ACLs.",
        "compliance": ["CIS GCP 5.1", "NIST 800-53 AC-3"]
    },
    
    # =========================================================================
    # FIREWALL/NETWORK FINDINGS
    # =========================================================================
    "OPEN_SSH_PORT": {
        "severity": Severity.CRITICAL,
        "description": "Firewall rule allows SSH (port 22) from any source (0.0.0.0/0)",
        "remediation": "Restrict SSH access to specific IP ranges or use IAP for SSH.",
        "compliance": ["CIS GCP 3.6", "NIST 800-53 SC-7", "PCI-DSS 1.2.1"]
    },
    "OPEN_RDP_PORT": {
        "severity": Severity.CRITICAL,
        "description": "Firewall rule allows RDP (port 3389) from any source (0.0.0.0/0)",
        "remediation": "Restrict RDP access to specific IP ranges or use IAP for RDP.",
        "compliance": ["CIS GCP 3.7", "NIST 800-53 SC-7", "PCI-DSS 1.2.1"]
    },
    "OPEN_FIREWALL": {
        "severity": Severity.CRITICAL,
        "description": "Firewall rule allows all traffic from any source",
        "remediation": "Restrict firewall rules to specific ports and source ranges.",
        "compliance": ["CIS GCP 3.9", "NIST 800-53 SC-7"]
    },
    "EGRESS_DENY_RULE_NOT_SET": {
        "severity": Severity.MEDIUM,
        "description": "No egress deny rule configured for VPC",
        "remediation": "Create a low-priority deny-all egress rule and allow specific traffic.",
        "compliance": ["PCI-DSS 7.2", "NIST 800-53 SC-7"]
    },
    "FIREWALL_RULE_LOGGING_DISABLED": {
        "severity": Severity.LOW,
        "description": "Firewall rule logging is not enabled",
        "remediation": "Enable logging on firewall rules for audit and troubleshooting.",
        "compliance": ["NIST 800-53 AU-2", "PCI-DSS 10.1"]
    },
    "OPEN_MYSQL_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows MySQL (port 3306) from any source",
        "remediation": "Restrict MySQL access to specific application servers only.",
        "compliance": ["NIST 800-53 SC-7", "PCI-DSS 1.2.1"]
    },
    "OPEN_POSTGRESQL_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows PostgreSQL (port 5432) from any source",
        "remediation": "Restrict PostgreSQL access to specific application servers only.",
        "compliance": ["NIST 800-53 SC-7", "PCI-DSS 1.2.1"]
    },
    "OPEN_MONGODB_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows MongoDB (port 27017) from any source",
        "remediation": "Restrict MongoDB access and enable authentication.",
        "compliance": ["NIST 800-53 SC-7", "PCI-DSS 1.2.1"]
    },
    "OPEN_REDIS_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows Redis (port 6379) from any source",
        "remediation": "Restrict Redis access and enable authentication.",
        "compliance": ["NIST 800-53 SC-7"]
    },
    "OPEN_ELASTICSEARCH_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows Elasticsearch (port 9200/9300) from any source",
        "remediation": "Restrict Elasticsearch access to specific clients.",
        "compliance": ["NIST 800-53 SC-7"]
    },
    "OPEN_HTTP_PORT": {
        "severity": Severity.MEDIUM,
        "description": "Firewall allows HTTP (port 80) from any source",
        "remediation": "Consider using HTTPS-only access via load balancers.",
        "compliance": ["NIST 800-53 SC-8"]
    },
    "OPEN_FTP_PORT": {
        "severity": Severity.HIGH,
        "description": "Firewall allows FTP (ports 20-21) from any source",
        "remediation": "Use SFTP/SCP instead of FTP for secure file transfer.",
        "compliance": ["NIST 800-53 SC-8", "PCI-DSS 4.1"]
    },
    "OPEN_TELNET_PORT": {
        "severity": Severity.CRITICAL,
        "description": "Firewall allows Telnet (port 23) from any source",
        "remediation": "Disable Telnet and use SSH for remote access.",
        "compliance": ["NIST 800-53 SC-8", "PCI-DSS 2.3"]
    },
    "OPEN_DNS_PORT": {
        "severity": Severity.MEDIUM,
        "description": "Firewall allows DNS (port 53) from any source",
        "remediation": "Restrict DNS access unless running a public DNS server.",
        "compliance": ["NIST 800-53 SC-7"]
    },
    "OPEN_SMTP_PORT": {
        "severity": Severity.MEDIUM,
        "description": "Firewall allows SMTP (port 25) from any source",
        "remediation": "Restrict SMTP access to mail servers only.",
        "compliance": ["NIST 800-53 SC-7"]
    },
    
    # =========================================================================
    # CLOUD SQL FINDINGS
    # =========================================================================
    "SQL_PUBLIC_IP": {
        "severity": Severity.CRITICAL,
        "description": "Cloud SQL instance has a public IP address",
        "remediation": "Use private IP only and connect via Cloud SQL Auth Proxy or VPC.",
        "compliance": ["CIS GCP 6.6", "NIST 800-53 SC-7"]
    },
    "SQL_SSL_NOT_ENFORCED": {
        "severity": Severity.HIGH,
        "description": "SSL/TLS connections are not required for Cloud SQL",
        "remediation": "Enable 'Require SSL' to encrypt connections.",
        "compliance": ["CIS GCP 6.1", "NIST 800-53 SC-8", "PCI-DSS 4.1"]
    },
    "SQL_AUTO_BACKUP_DISABLED": {
        "severity": Severity.MEDIUM,
        "description": "Automated backups are not enabled for Cloud SQL",
        "remediation": "Enable automated backups with appropriate retention period.",
        "compliance": ["CIS GCP 6.7", "NIST 800-53 CP-9"]
    },
    "SQL_NO_ROOT_PASSWORD": {
        "severity": Severity.CRITICAL,
        "description": "Cloud SQL root user has no password set",
        "remediation": "Set a strong password for the root/admin user.",
        "compliance": ["CIS GCP 6.3", "NIST 800-53 IA-5", "PCI-DSS 8.2"]
    },
    "SQL_AUTHORIZED_NETWORKS_WIDE": {
        "severity": Severity.HIGH,
        "description": "Cloud SQL authorized networks include 0.0.0.0/0",
        "remediation": "Restrict authorized networks to specific IP ranges.",
        "compliance": ["CIS GCP 6.5", "NIST 800-53 SC-7"]
    },
    "SQL_LOCAL_INFILE_ENABLED": {
        "severity": Severity.MEDIUM,
        "description": "MySQL local_infile flag is enabled",
        "remediation": "Disable local_infile to prevent local file loading attacks.",
        "compliance": ["CIS GCP 6.1.2", "NIST 800-53 CM-7"]
    },
    "SQL_CROSS_DB_OWNERSHIP_ENABLED": {
        "severity": Severity.MEDIUM,
        "description": "SQL Server cross db ownership chaining is enabled",
        "remediation": "Disable cross database ownership chaining.",
        "compliance": ["CIS GCP 6.3.1", "NIST 800-53 AC-6"]
    },
    "SQL_CONTAINED_DATABASE_AUTH": {
        "severity": Severity.MEDIUM,
        "description": "SQL Server contained database authentication is enabled",
        "remediation": "Disable contained database authentication.",
        "compliance": ["CIS GCP 6.3.2", "NIST 800-53 IA-2"]
    },
    "SQL_LOG_CHECKPOINTS_DISABLED": {
        "severity": Severity.LOW,
        "description": "PostgreSQL log_checkpoints is disabled",
        "remediation": "Enable log_checkpoints for performance monitoring.",
        "compliance": ["CIS GCP 6.2.1"]
    },
    "SQL_LOG_CONNECTIONS_DISABLED": {
        "severity": Severity.LOW,
        "description": "PostgreSQL log_connections is disabled",
        "remediation": "Enable log_connections for audit trail.",
        "compliance": ["CIS GCP 6.2.2", "NIST 800-53 AU-2"]
    },
    "SQL_LOG_DISCONNECTIONS_DISABLED": {
        "severity": Severity.LOW,
        "description": "PostgreSQL log_disconnections is disabled",
        "remediation": "Enable log_disconnections for complete session logging.",
        "compliance": ["CIS GCP 6.2.3", "NIST 800-53 AU-2"]
    },
    "SQL_LOG_LOCK_WAITS_DISABLED": {
        "severity": Severity.LOW,
        "description": "PostgreSQL log_lock_waits is disabled",
        "remediation": "Enable log_lock_waits to detect deadlocks.",
        "compliance": ["CIS GCP 6.2.4"]
    },
}


# =============================================================================
# PROGRESS TRACKER
# =============================================================================

class ProgressTracker:
    """Thread-safe progress tracker with visual progress bar"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._total = 0
        self._completed = 0
        self._current_phase = ""
        self._pbar = None
    
    def set_total(self, total: int, description: str = "Scanning"):
        with self._lock:
            self._total = total
            self._completed = 0
            self._current_phase = description
            if TQDM_AVAILABLE:
                self._pbar = tqdm(total=total, desc=description, unit="item", 
                                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
            else:
                print(f"\n{description}: 0/{total} (0%)")
    
    def increment(self, count: int = 1):
        with self._lock:
            self._completed += count
            if self._pbar:
                self._pbar.update(count)
            elif self._total > 0:
                pct = (self._completed / self._total) * 100
                print(f"\r{self._current_phase}: {self._completed}/{self._total} ({pct:.1f}%)", end="", flush=True)
    
    def set_phase(self, phase: str):
        with self._lock:
            self._current_phase = phase
            if self._pbar:
                self._pbar.set_description(phase)
    
    def close(self):
        with self._lock:
            if self._pbar:
                self._pbar.close()
            else:
                print()  # Newline after progress


# =============================================================================
# ERROR HANDLER
# =============================================================================

class ErrorHandler:
    """Silent error handler that logs to file"""
    
    def __init__(self, log_file: str = "scanner_errors.log"):
        self.log_file = log_file
        self._lock = threading.Lock()
        logging.basicConfig(
            filename=log_file,
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("GCPScanner")
    
    def log(self, error: Exception, context: str = ""):
        with self._lock:
            self.logger.error(f"{context}: {str(error)}")


# =============================================================================
# GCP SECURITY SCANNER
# =============================================================================

class GCPSecurityScanner:
    """
    Multi-resource GCP security scanner with SCC-compatible output.
    
    Features:
    - Parallel processing with quota management
    - Progress tracking with visual progress bar
    - Silent error handling (logs to file)
    - Zero-cost operations (metadata only)
    """
    
    def __init__(
        self,
        org_id: Optional[str] = None,
        project_ids: Optional[List[str]] = None,
        max_workers: int = 10
    ):
        self.org_id = org_id
        self.project_ids = project_ids or []
        self.max_workers = max_workers
        self.progress = ProgressTracker()
        self.errors = ErrorHandler()
        self.findings: List[Finding] = []
        self._lock = threading.Lock()
        
        # API clients (initialized lazily)
        self._compute_client = None
        self._container_client = None
        self._storage_client = None
        self._sqladmin_client = None
        self._rm_client = None
    
    # =========================================================================
    # API CLIENT PROPERTIES
    # =========================================================================
    
    @property
    def compute_client(self):
        if not self._compute_client:
            self._compute_client = compute_v1.InstancesClient()
        return self._compute_client
    
    @property
    def container_client(self):
        if not self._container_client:
            self._container_client = container_v1.ClusterManagerClient()
        return self._container_client
    
    @property
    def storage_client(self):
        if not self._storage_client:
            self._storage_client = storage.Client()
        return self._storage_client
    
    @property
    def sqladmin_client(self):
        if not self._sqladmin_client:
            credentials, project = google_auth_default()
            self._sqladmin_client = discovery.build('sqladmin', 'v1beta4', credentials=credentials, cache_discovery=False)
        return self._sqladmin_client
    
    @property
    def rm_client(self):
        if not self._rm_client:
            self._rm_client = resourcemanager_v3.ProjectsClient()
        return self._rm_client
    
    # =========================================================================
    # PROJECT DISCOVERY
    # =========================================================================
    
    def discover_projects(self) -> List[str]:
        """Discover projects from org or use provided list"""
        if self.project_ids:
            return self.project_ids
        
        if not self.org_id:
            raise ValueError("Either org_id or project_ids must be provided")
        
        projects = []
        try:
            request = resourcemanager_v3.SearchProjectsRequest(
                query=f"parent:organizations/{self.org_id}"
            )
            for project in self.rm_client.search_projects(request=request):
                if project.state.name == "ACTIVE":
                    projects.append(project.project_id)
        except Exception as e:
            self.errors.log(e, "Project discovery")
        
        return projects
    
    # =========================================================================
    # FINDING CREATION HELPER
    # =========================================================================
    
    def _create_finding(
        self,
        category: str,
        resource_name: str,
        resource_type: str,
        project: str,
        location: str
    ) -> Finding:
        """Create a finding from the definitions"""
        defn = FINDING_DEFINITIONS.get(category, {})
        finding_id = f"projects/{project}/sources/scanner/findings/{category}-{hash(resource_name) % 10**8}"
        
        return Finding(
            name=finding_id,
            category=category,
            severity=defn.get("severity", Severity.INFO),
            state=FindingState.ACTIVE,
            finding_class=FindingClass.MISCONFIGURATION,
            resource_name=resource_name,
            resource_type=resource_type,
            resource_project=project,
            resource_location=location,
            description=defn.get("description", ""),
            remediation=defn.get("remediation", ""),
            compliance=defn.get("compliance", [])
        )
    
    def _add_finding(self, finding: Finding):
        """Thread-safe finding addition"""
        with self._lock:
            self.findings.append(finding)
    
    # =========================================================================
    # COMPUTE SCANNER
    # =========================================================================
    
    def _scan_compute_instance(self, project: str, zone: str, instance) -> List[Finding]:
        """Scan a single compute instance for security issues"""
        findings = []
        resource_name = f"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{instance.name}"
        resource_type = "compute.googleapis.com/Instance"
        
        try:
            # Skip GKE nodes
            if instance.name.startswith("gke-"):
                return findings
            
            # FULL_API_ACCESS - Check for cloud-platform scope
            if instance.service_accounts:
                for sa in instance.service_accounts:
                    if sa.scopes:
                        for scope in sa.scopes:
                            if "cloud-platform" in scope:
                                findings.append(self._create_finding(
                                    "FULL_API_ACCESS", resource_name, resource_type, project, zone
                                ))
                                break
            
            # PUBLIC_IP_ADDRESS
            if instance.network_interfaces:
                for nic in instance.network_interfaces:
                    if nic.access_configs:
                        for ac in nic.access_configs:
                            if ac.nat_i_p:
                                findings.append(self._create_finding(
                                    "PUBLIC_IP_ADDRESS", resource_name, resource_type, project, zone
                                ))
                                break
            
            # COMPUTE_SECURE_BOOT_DISABLED
            if instance.shielded_instance_config:
                if not instance.shielded_instance_config.enable_secure_boot:
                    findings.append(self._create_finding(
                        "COMPUTE_SECURE_BOOT_DISABLED", resource_name, resource_type, project, zone
                    ))
                if not instance.shielded_instance_config.enable_integrity_monitoring:
                    findings.append(self._create_finding(
                        "INTEGRITY_MONITORING_DISABLED", resource_name, resource_type, project, zone
                    ))
                if not instance.shielded_instance_config.enable_vtpm:
                    findings.append(self._create_finding(
                        "VTPM_DISABLED", resource_name, resource_type, project, zone
                    ))
            else:
                findings.append(self._create_finding(
                    "COMPUTE_SECURE_BOOT_DISABLED", resource_name, resource_type, project, zone
                ))
            
            # CONFIDENTIAL_COMPUTING_DISABLED (only for N2D machines)
            if instance.machine_type and "n2d-" in instance.machine_type.lower():
                if not instance.confidential_instance_config or not instance.confidential_instance_config.enable_confidential_compute:
                    findings.append(self._create_finding(
                        "CONFIDENTIAL_COMPUTING_DISABLED", resource_name, resource_type, project, zone
                    ))
            
            # IP_FORWARDING_ENABLED
            if instance.can_ip_forward:
                findings.append(self._create_finding(
                    "IP_FORWARDING_ENABLED", resource_name, resource_type, project, zone
                ))
            
            # COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED
            block_project_keys = False
            if instance.metadata and instance.metadata.items:
                for item in instance.metadata.items:
                    if item.key == "block-project-ssh-keys" and item.value.lower() == "true":
                        block_project_keys = True
                        break
            if not block_project_keys:
                findings.append(self._create_finding(
                    "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED", resource_name, resource_type, project, zone
                ))
            
            # DEFAULT_SERVICE_ACCOUNT_USED
            if instance.service_accounts:
                for sa in instance.service_accounts:
                    if "-compute@developer.gserviceaccount.com" in sa.email:
                        findings.append(self._create_finding(
                            "DEFAULT_SERVICE_ACCOUNT_USED", resource_name, resource_type, project, zone
                        ))
                        break
            
            # SERIAL_PORT_ENABLED
            if instance.metadata and instance.metadata.items:
                for item in instance.metadata.items:
                    if item.key == "serial-port-enable" and item.value.lower() == "true":
                        findings.append(self._create_finding(
                            "SERIAL_PORT_ENABLED", resource_name, resource_type, project, zone
                        ))
                        break
            
            # DELETION_PROTECTION_DISABLED
            if not instance.deletion_protection:
                findings.append(self._create_finding(
                    "DELETION_PROTECTION_DISABLED", resource_name, resource_type, project, zone
                ))
            
        except Exception as e:
            self.errors.log(e, f"Scanning instance {instance.name}")
        
        return findings
    
    def scan_compute(self, project: str) -> List[Finding]:
        """Scan all compute instances in a project"""
        findings = []
        try:
            zones_client = compute_v1.ZonesClient()
            instances_client = compute_v1.InstancesClient()
            
            # Get all zones
            zones = list(zones_client.list(project=project))
            
            for zone in zones:
                zone_name = zone.name
                try:
                    instances = list(instances_client.list(project=project, zone=zone_name))
                    for instance in instances:
                        instance_findings = self._scan_compute_instance(project, zone_name, instance)
                        findings.extend(instance_findings)
                        self.progress.increment()
                except Exception as e:
                    self.errors.log(e, f"Listing instances in {zone_name}")
                    
        except Exception as e:
            self.errors.log(e, f"Compute scan for {project}")
        
        return findings
    
    # =========================================================================
    # GKE SCANNER
    # =========================================================================
    
    def scan_gke(self, project: str) -> List[Finding]:
        """Scan all GKE clusters in a project"""
        findings = []
        try:
            parent = f"projects/{project}/locations/-"
            clusters = self.container_client.list_clusters(parent=parent).clusters
            
            for cluster in clusters:
                resource_name = f"//container.googleapis.com/projects/{project}/locations/{cluster.location}/clusters/{cluster.name}"
                resource_type = "container.googleapis.com/Cluster"
                location = cluster.location
                
                # PRIVATE_CLUSTER_DISABLED
                if not cluster.private_cluster_config or not cluster.private_cluster_config.enable_private_nodes:
                    findings.append(self._create_finding(
                        "PRIVATE_CLUSTER_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # MASTER_AUTHORIZED_NETWORKS_DISABLED
                if not cluster.master_authorized_networks_config or not cluster.master_authorized_networks_config.enabled:
                    findings.append(self._create_finding(
                        "MASTER_AUTHORIZED_NETWORKS_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # CLUSTER_SHIELDED_NODES_DISABLED
                if not cluster.shielded_nodes or not cluster.shielded_nodes.enabled:
                    findings.append(self._create_finding(
                        "CLUSTER_SHIELDED_NODES_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # WORKLOAD_IDENTITY_DISABLED
                if not cluster.workload_identity_config or not cluster.workload_identity_config.workload_pool:
                    findings.append(self._create_finding(
                        "WORKLOAD_IDENTITY_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # LEGACY_AUTHORIZATION_ENABLED
                if cluster.legacy_abac and cluster.legacy_abac.enabled:
                    findings.append(self._create_finding(
                        "LEGACY_AUTHORIZATION_ENABLED", resource_name, resource_type, project, location
                    ))
                
                # CLUSTER_LOGGING_DISABLED
                if not cluster.logging_service or cluster.logging_service == "none":
                    findings.append(self._create_finding(
                        "CLUSTER_LOGGING_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # CLUSTER_MONITORING_DISABLED
                if not cluster.monitoring_service or cluster.monitoring_service == "none":
                    findings.append(self._create_finding(
                        "CLUSTER_MONITORING_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # NETWORK_POLICY_DISABLED
                if not cluster.network_policy or not cluster.network_policy.enabled:
                    findings.append(self._create_finding(
                        "NETWORK_POLICY_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # BINARY_AUTHORIZATION_DISABLED
                if not cluster.binary_authorization or not cluster.binary_authorization.enabled:
                    findings.append(self._create_finding(
                        "BINARY_AUTHORIZATION_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # ALPHA_CLUSTER_ENABLED
                if cluster.enable_kubernetes_alpha:
                    findings.append(self._create_finding(
                        "ALPHA_CLUSTER_ENABLED", resource_name, resource_type, project, location
                    ))
                
                # Check node pools
                for pool in cluster.node_pools:
                    if pool.management:
                        if not pool.management.auto_repair:
                            findings.append(self._create_finding(
                                "AUTO_REPAIR_DISABLED", resource_name, resource_type, project, location
                            ))
                        if not pool.management.auto_upgrade:
                            findings.append(self._create_finding(
                                "AUTO_UPGRADE_DISABLED", resource_name, resource_type, project, location
                            ))
                
                self.progress.increment()
                
        except Exception as e:
            self.errors.log(e, f"GKE scan for {project}")
        
        return findings
    
    # =========================================================================
    # STORAGE SCANNER
    # =========================================================================
    
    def scan_storage(self, project: str) -> List[Finding]:
        """Scan all Cloud Storage buckets in a project (metadata only - no object reads)"""
        findings = []
        try:
            # List buckets (metadata only, no cost)
            buckets = list(self.storage_client.list_buckets(project=project))
            
            for bucket in buckets:
                resource_name = f"//storage.googleapis.com/projects/_/buckets/{bucket.name}"
                resource_type = "storage.googleapis.com/Bucket"
                location = bucket.location or "global"
                
                # PUBLIC_BUCKET_ACL - Check IAM policy
                try:
                    policy = bucket.get_iam_policy()
                    for binding in policy.bindings:
                        members = binding.get("members", [])
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            findings.append(self._create_finding(
                                "PUBLIC_BUCKET_ACL", resource_name, resource_type, project, location
                            ))
                            break
                except Exception as e:
                    self.errors.log(e, f"Getting IAM policy for {bucket.name}")
                
                # BUCKET_POLICY_ONLY_DISABLED
                iam_config = bucket.iam_configuration
                if not iam_config or not iam_config.uniform_bucket_level_access_enabled:
                    findings.append(self._create_finding(
                        "BUCKET_POLICY_ONLY_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # BUCKET_LOGGING_DISABLED
                if not bucket.logging:
                    findings.append(self._create_finding(
                        "BUCKET_LOGGING_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # OBJECT_VERSIONING_DISABLED
                if not bucket.versioning_enabled:
                    findings.append(self._create_finding(
                        "OBJECT_VERSIONING_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # PUBLIC_ACCESS_PREVENTION_DISABLED
                if iam_config:
                    pap = getattr(iam_config, 'public_access_prevention', None)
                    if not pap or pap != 'enforced':
                        findings.append(self._create_finding(
                            "PUBLIC_ACCESS_PREVENTION_DISABLED", resource_name, resource_type, project, location
                        ))
                
                # BUCKET_RETENTION_POLICY_NOT_LOCKED
                if bucket.retention_policy and not bucket.retention_policy_locked:
                    findings.append(self._create_finding(
                        "BUCKET_RETENTION_POLICY_NOT_LOCKED", resource_name, resource_type, project, location
                    ))
                
                self.progress.increment()
                
        except Exception as e:
            self.errors.log(e, f"Storage scan for {project}")
        
        return findings
    
    # =========================================================================
    # FIREWALL SCANNER
    # =========================================================================
    
    def _is_open_to_internet(self, source_ranges: List[str]) -> bool:
        """Check if firewall rule is open to the entire internet"""
        open_ranges = {"0.0.0.0/0", "::/0"}
        return bool(set(source_ranges or []) & open_ranges)
    
    def _check_port(self, allowed: List, port: int) -> bool:
        """Check if a specific port is allowed"""
        for rule in allowed:
            if rule.I_p_protocol in ["all", "tcp", "udp"]:
                if not rule.ports:
                    return True  # All ports allowed
                for port_spec in rule.ports:
                    if "-" in port_spec:
                        start, end = map(int, port_spec.split("-"))
                        if start <= port <= end:
                            return True
                    elif port_spec == str(port):
                        return True
        return False
    
    def scan_firewall(self, project: str) -> List[Finding]:
        """Scan VPC firewall rules for security issues"""
        findings = []
        has_egress_deny = False
        
        try:
            firewalls_client = compute_v1.FirewallsClient()
            rules = list(firewalls_client.list(project=project))
            
            for rule in rules:
                resource_name = f"//compute.googleapis.com/projects/{project}/global/firewalls/{rule.name}"
                resource_type = "compute.googleapis.com/Firewall"
                location = "global"
                
                # Skip GKE auto-created rules
                if rule.name.startswith("gke-") or rule.name.startswith("k8s-"):
                    continue
                
                # Check for egress deny rule
                if rule.direction == "EGRESS" and rule.denied:
                    for denied in rule.denied:
                        if denied.I_p_protocol == "all":
                            has_egress_deny = True
                            break
                
                # Only check ingress rules from internet
                if rule.direction != "INGRESS" or not self._is_open_to_internet(rule.source_ranges):
                    self.progress.increment()
                    continue
                
                # OPEN_FIREWALL - All traffic allowed
                if rule.allowed:
                    for allowed in rule.allowed:
                        if allowed.I_p_protocol == "all" and not allowed.ports:
                            findings.append(self._create_finding(
                                "OPEN_FIREWALL", resource_name, resource_type, project, location
                            ))
                            break
                
                # Check specific dangerous ports
                port_findings = [
                    (22, "OPEN_SSH_PORT"),
                    (3389, "OPEN_RDP_PORT"),
                    (23, "OPEN_TELNET_PORT"),
                    (21, "OPEN_FTP_PORT"),
                    (3306, "OPEN_MYSQL_PORT"),
                    (5432, "OPEN_POSTGRESQL_PORT"),
                    (27017, "OPEN_MONGODB_PORT"),
                    (6379, "OPEN_REDIS_PORT"),
                    (9200, "OPEN_ELASTICSEARCH_PORT"),
                    (80, "OPEN_HTTP_PORT"),
                    (53, "OPEN_DNS_PORT"),
                    (25, "OPEN_SMTP_PORT"),
                ]
                
                for port, finding_category in port_findings:
                    if self._check_port(rule.allowed, port):
                        findings.append(self._create_finding(
                            finding_category, resource_name, resource_type, project, location
                        ))
                
                # FIREWALL_RULE_LOGGING_DISABLED
                if not rule.log_config or not rule.log_config.enable:
                    findings.append(self._create_finding(
                        "FIREWALL_RULE_LOGGING_DISABLED", resource_name, resource_type, project, location
                    ))
                
                self.progress.increment()
            
            # EGRESS_DENY_RULE_NOT_SET (project-level finding)
            if not has_egress_deny:
                findings.append(self._create_finding(
                    "EGRESS_DENY_RULE_NOT_SET",
                    f"//compute.googleapis.com/projects/{project}",
                    "compute.googleapis.com/Project",
                    project,
                    "global"
                ))
                
        except Exception as e:
            self.errors.log(e, f"Firewall scan for {project}")
        
        return findings
    
    # =========================================================================
    # CLOUD SQL SCANNER
    # =========================================================================
    
    def scan_cloudsql(self, project: str) -> List[Finding]:
        """Scan Cloud SQL instances for security issues"""
        findings = []
        try:
            # Use discovery API for SQL Admin
            response = self.sqladmin_client.instances().list(project=project).execute()
            instances = response.get('items', [])
            
            for instance in instances:
                instance_name = instance.get('name', '')
                resource_name = f"//sqladmin.googleapis.com/projects/{project}/instances/{instance_name}"
                resource_type = "sqladmin.googleapis.com/Instance"
                location = instance.get('region', instance.get('gceZone', 'global'))
                
                settings = instance.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})
                
                # SQL_PUBLIC_IP
                if ip_config.get('ipv4Enabled', False):
                    findings.append(self._create_finding(
                        "SQL_PUBLIC_IP", resource_name, resource_type, project, location
                    ))
                
                # SQL_SSL_NOT_ENFORCED
                if not ip_config.get('requireSsl', False):
                    findings.append(self._create_finding(
                        "SQL_SSL_NOT_ENFORCED", resource_name, resource_type, project, location
                    ))
                
                # SQL_AUTHORIZED_NETWORKS_WIDE
                auth_networks = ip_config.get('authorizedNetworks', [])
                for network in auth_networks:
                    if network.get('value') == "0.0.0.0/0":
                        findings.append(self._create_finding(
                            "SQL_AUTHORIZED_NETWORKS_WIDE", resource_name, resource_type, project, location
                        ))
                        break
                
                # SQL_AUTO_BACKUP_DISABLED
                backup_config = settings.get('backupConfiguration', {})
                if not backup_config.get('enabled', False):
                    findings.append(self._create_finding(
                        "SQL_AUTO_BACKUP_DISABLED", resource_name, resource_type, project, location
                    ))
                
                # Database flags
                db_flags = settings.get('databaseFlags', [])
                flags = {f.get('name'): f.get('value') for f in db_flags}
                db_type = instance.get('databaseVersion', '')
                
                # MySQL flags
                if "MYSQL" in db_type.upper():
                    if flags.get("local_infile") == "on":
                        findings.append(self._create_finding(
                            "SQL_LOCAL_INFILE_ENABLED", resource_name, resource_type, project, location
                        ))
                
                # PostgreSQL flags
                if "POSTGRES" in db_type.upper():
                    if flags.get("log_checkpoints") == "off":
                        findings.append(self._create_finding(
                            "SQL_LOG_CHECKPOINTS_DISABLED", resource_name, resource_type, project, location
                        ))
                    if flags.get("log_connections") == "off":
                        findings.append(self._create_finding(
                            "SQL_LOG_CONNECTIONS_DISABLED", resource_name, resource_type, project, location
                        ))
                    if flags.get("log_disconnections") == "off":
                        findings.append(self._create_finding(
                            "SQL_LOG_DISCONNECTIONS_DISABLED", resource_name, resource_type, project, location
                        ))
                    if flags.get("log_lock_waits") == "off":
                        findings.append(self._create_finding(
                            "SQL_LOG_LOCK_WAITS_DISABLED", resource_name, resource_type, project, location
                        ))
                
                # SQL Server flags
                if "SQLSERVER" in db_type.upper():
                    if flags.get("cross db ownership chaining") == "on":
                        findings.append(self._create_finding(
                            "SQL_CROSS_DB_OWNERSHIP_ENABLED", resource_name, resource_type, project, location
                        ))
                    if flags.get("contained database authentication") == "on":
                        findings.append(self._create_finding(
                            "SQL_CONTAINED_DATABASE_AUTH", resource_name, resource_type, project, location
                        ))
                
                self.progress.increment()
                
        except Exception as e:
            self.errors.log(e, f"Cloud SQL scan for {project}")
        
        return findings
    
    # =========================================================================
    # MAIN SCAN ORCHESTRATOR
    # =========================================================================
    
    def scan(self) -> List[Finding]:
        """Execute full security scan across all resources"""
        print("\n" + "=" * 60)
        print("GCP Security Health Analytics Scanner")
        print("=" * 60)
        
        # Discover projects
        print("\n[1/6] Discovering projects...")
        projects = self.discover_projects()
        if not projects:
            print("ERROR: No projects found to scan.")
            return []
        print(f"      Found {len(projects)} project(s): {', '.join(projects[:5])}" + 
              (f"... (+{len(projects)-5} more)" if len(projects) > 5 else ""))
        
        scan_phases = [
            ("Compute Instances", self.scan_compute),
            ("GKE Clusters", self.scan_gke),
            ("Storage Buckets", self.scan_storage),
            ("Firewall Rules", self.scan_firewall),
            ("Cloud SQL Instances", self.scan_cloudsql),
        ]
        
        all_findings: List[Finding] = []
        
        for idx, (phase_name, scan_func) in enumerate(scan_phases, start=2):
            print(f"\n[{idx}/6] Scanning {phase_name}...")
            
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(projects))) as executor:
                futures = {executor.submit(scan_func, proj): proj for proj in projects}
                
                for future in as_completed(futures):
                    proj = futures[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        self.errors.log(e, f"{phase_name} scan for {proj}")
            
            print(f"      Found {len([f for f in all_findings if phase_name.split()[0].upper() in f.resource_type.upper()])} findings")
        
        self.findings = all_findings
        return all_findings
    
    # =========================================================================
    # EXPORT
    # =========================================================================
    
    def export_csv(self, filename: Optional[str] = None) -> str:
        """Export findings to SCC-compatible CSV format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_findings_{timestamp}.csv"
        
        fieldnames = [
            "finding_name", "finding_category", "finding_severity", "finding_state",
            "finding_class", "resource_name", "resource_type", "resource_project",
            "resource_location", "finding_description", "remediation", "compliance",
            "scan_time"
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding.to_dict())
        
        return filename
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"\nTotal Findings: {len(self.findings)}")
        print(f"  CRITICAL: {severity_counts.get('CRITICAL', 0)}")
        print(f"  HIGH:     {severity_counts.get('HIGH', 0)}")
        print(f"  MEDIUM:   {severity_counts.get('MEDIUM', 0)}")
        print(f"  LOW:      {severity_counts.get('LOW', 0)}")
        
        # Count by resource type
        print("\nFindings by Resource Type:")
        resource_counts = {}
        for finding in self.findings:
            rt = finding.resource_type.split("/")[-1]
            resource_counts[rt] = resource_counts.get(rt, 0) + 1
        for rt, count in sorted(resource_counts.items(), key=lambda x: -x[1]):
            print(f"  {rt}: {count}")
        
        # Top categories
        print("\nTop Finding Categories:")
        category_counts = {}
        for finding in self.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {cat}: {count}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="GCP Security Health Analytics Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --org-id 123456789
  %(prog)s --project-ids project1,project2,project3
  %(prog)s --project-ids project1 --output results.csv

This scanner performs READ-ONLY operations and does NOT modify any infrastructure.
All errors are logged silently to scanner_errors.log.
        """
    )
    
    parser.add_argument(
        "--org-id",
        help="GCP Organization ID to scan all projects"
    )
    parser.add_argument(
        "--project-ids",
        help="Comma-separated list of project IDs to scan"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output CSV filename (default: security_findings_<timestamp>.csv)"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum parallel workers (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.org_id and not args.project_ids:
        parser.error("Either --org-id or --project-ids must be provided")
    
    project_ids = None
    if args.project_ids:
        project_ids = [p.strip() for p in args.project_ids.split(",")]
    
    # Create scanner and run
    scanner = GCPSecurityScanner(
        org_id=args.org_id,
        project_ids=project_ids,
        max_workers=args.max_workers
    )
    
    start_time = time.time()
    findings = scanner.scan()
    elapsed = time.time() - start_time
    
    if findings:
        output_file = scanner.export_csv(args.output)
        scanner.print_summary()
        print(f"\nResults exported to: {output_file}")
    else:
        print("\nNo findings detected. Your infrastructure looks secure! 🎉")
    
    print(f"\nScan completed in {elapsed:.1f} seconds")
    print("Errors (if any) logged to: scanner_errors.log")


if __name__ == "__main__":
    main()
