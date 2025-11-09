import kopf
import kubernetes
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any

# Set more verbose logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    settings.persistence.finalizer = 'grype-operator.security.io/finalizer'
    settings.posting.level = logging.DEBUG
    settings.watching.server_timeout = 60
    # Run cluster-wide to avoid the namespace warning
    settings.watching.clusterwide = True
    logger.info("Grype Operator starting up...")

@kopf.on.create('pods')
@kopf.on.update('pods') 
def handle_pod(spec, name, namespace, labels, uid, body, **kwargs):
    """
    Create scan jobs for pod images when pods are created or updated
    """
    logger.info(f"=== HANDLING POD: {namespace}/{name} ===")
    logger.debug(f"Pod spec: {spec}")
    logger.debug(f"Pod labels: {labels}")
    logger.debug(f"Pod annotations: {kwargs.get('annotations', {})}")
    
    # Skip if already processed (check annotation)
    annotations = kwargs.get('annotations', {})
    if annotations.get('grype-operator.security.io/scan-scheduled') == 'true':
        logger.info(f"Pod {namespace}/{name} already has scan scheduled, skipping")
        return
    
    # Skip system namespaces
    excluded_namespaces = ['kube-system', 'kube-public', 'kube-node-lease', 'grype-operator-system']
    if namespace in excluded_namespaces:
        logger.info(f"Skipping system namespace: {namespace}")
        return
    
    # Skip scan job pods themselves (prevent infinite recursion)
    if labels.get('app') == 'grype-scanner':
        logger.info(f"Skipping scan job pod: {namespace}/{name}")
        return
    
    # Skip pods created by jobs (scan jobs)
    if labels.get('job-name') and 'grype-scan' in labels.get('job-name', ''):
        logger.info(f"Skipping job pod: {namespace}/{name}")
        return
    
    # Skip pods with grype-operator managed labels
    if labels.get('grype-operator.security.io/managed') == 'true':
        logger.info(f"Skipping operator-managed pod: {namespace}/{name}")
        return
    
    containers = spec.get('containers', [])
    init_containers = spec.get('initContainers', [])
    
    all_containers = containers + init_containers
    logger.info(f"Found {len(all_containers)} containers in pod {namespace}/{name}")
    
    # Create scan jobs for each unique image
    scanned_images = set()
    for container in all_containers:
        image = container.get('image')
        container_name = container.get('name')
        logger.info(f"Processing container: {container_name} with image: {image}")
        
        if image and image not in scanned_images:
            logger.info(f"Creating scan job for image: {image} (container: {container_name})")
            create_scan_job(
                namespace=namespace,
                pod_name=name,
                pod_uid=uid,
                container_name=container_name,
                image=image
            )
            scanned_images.add(image)
        else:
            logger.info(f"Skipping image {image} - already scanned or invalid")
    
    # Annotate pod as scan scheduled
    if scanned_images:
        logger.info(f"Annotating pod {namespace}/{name} with scan schedule")
        api = kubernetes.client.CoreV1Api()
        patch_body = {
            "metadata": {
                "annotations": {
                    "grype-operator.security.io/scan-scheduled": "true",
                    "grype-operator.security.io/schedule-time": datetime.utcnow().isoformat(),
                    "grype-operator.security.io/images-count": str(len(scanned_images))
                }
            }
        }
        try:
            api.patch_namespaced_pod(name, namespace, patch_body)
            logger.info(f"Successfully annotated pod {namespace}/{name}")
        except Exception as e:
            logger.error(f"Failed to annotate pod {namespace}/{name}: {e}")
    else:
        logger.info(f"No images to scan in pod {namespace}/{name}")

def create_scan_job(namespace: str, pod_name: str, pod_uid: str, 
                    container_name: str, image: str):
    """
    Create a Kubernetes Job to scan the image
    """
    logger.info(f"Creating scan job in namespace {namespace} for image {image}")
    
    batch_api = kubernetes.client.BatchV1Api()
    
    # Generate unique job name
    image_hash = hashlib.md5(image.encode()).hexdigest()[:8]
    job_name = f"grype-scan-{pod_name}-{image_hash}"[:63]
    report_name = f"{pod_name}-{image_hash}-report"
    
    # Escape image name for shell
    escaped_image = image.replace('"', '\\"').replace('$', '\\$')
    
    # Create job manifest
    job = {
        'apiVersion': 'batch/v1',
        'kind': 'Job',
        'metadata': {
            'name': job_name,
            'namespace': namespace,
            'labels': {
                'app': 'grype-scanner',
                'grype-operator.security.io/pod': pod_name,
                'grype-operator.security.io/managed': 'true',
                'grype-operator.security.io/job': 'true'
            },
            'ownerReferences': [{
                'apiVersion': 'v1',
                'kind': 'Pod',
                'name': pod_name,
                'uid': pod_uid,
                'blockOwnerDeletion': False
            }]
        },
        'spec': {
            'ttlSecondsAfterFinished': 3600,
            'backoffLimit': 3,
            'template': {
                'metadata': {
                    'labels': {
                        'app': 'grype-scanner',
                        'grype-operator.security.io/pod': pod_name,
                        'grype-operator.security.io/managed': 'true',
                        'grype-operator.security.io/job': 'true'
                    }
                },
                'spec': {
                    'restartPolicy': 'Never',
                    'serviceAccountName': 'grype-scanner',
                    'containers': [{
                        'name': 'grype-scanner',
                        'image': 'alpine:latest',
                        'command': ['/bin/sh'],
                        'args': [
                            '-c',
                            f'''#!/bin/sh
# Install kubectl first
echo "Installing kubectl..."
apk add --no-cache curl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
mv ./kubectl /usr/local/bin/kubectl

# Install grype using official method
echo "Installing Grype..."
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

echo "=== Starting Grype Scan ==="
echo "Image: {escaped_image}"
echo "Pod: {pod_name}, Container: {container_name}"
echo "Namespace: {namespace}"

# Update grype database
echo "Updating Grype database..."
grype db update || echo "Database update failed, but continuing..."

# Run grype scan
echo "Running Grype scan..."
grype "{escaped_image}" -o json --quiet > /tmp/scan-results.json 2>/tmp/scan-errors.log || {{
    SCAN_EXIT_CODE=$?
    echo "Grype scan failed with exit code: $SCAN_EXIT_CODE"
    echo "Error output:"
    cat /tmp/scan-errors.log
    echo "Creating fallback report..."
    cat > /tmp/scan-results.json << 'FALLBACK_EOF'
{{
    "matches": [],
    "source": {{
        "target": "{escaped_image}",
        "type": "image"
    }},
    "distro": {{
        "name": "unknown",
        "version": "unknown"
    }},
    "descriptor": {{
        "name": "grype",
        "version": "unknown"
    }}
}}
FALLBACK_EOF
}}

echo "Scan completed, processing results..."

# Install Python for processing
apk add --no-cache python3

# Process results with Python
python3 << 'PYTHON_EOF'
import json
import sys
import os
from datetime import datetime
import subprocess

try:
    with open("/tmp/scan-results.json", "r") as f:
        data = json.load(f)
    print("Successfully loaded scan results")
except Exception as e:
    print(f"Error loading scan results: {{e}}")
    data = {{"matches": []}}

matches = data.get("matches", [])
vulnerabilities = []
summary = {{"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0, "total": 0}}

for match in matches:
    vuln = match.get("vulnerability", {{}})
    artifact = match.get("artifact", {{}})
    severity = vuln.get("severity", "Unknown").lower()
    
    vuln_data = {{
        "id": vuln.get("id", "UNKNOWN"),
        "severity": vuln.get("severity", "Unknown"),
        "package": artifact.get("name", "unknown"),
        "version": artifact.get("version", "unknown"),
        "fixedVersion": vuln.get("fix", {{}}).get("versions", []),
        "description": vuln.get("description", "")[:200]
    }}
    vulnerabilities.append(vuln_data)
    
    if severity in summary:
        summary[severity] += 1
    else:
        summary["unknown"] += 1
    summary["total"] += 1

print(f"Found {{summary['total']}} vulnerabilities")

# Create VulnerabilityReport
report_name = "{report_name}"
report = {{
    "apiVersion": "security.grype.io/v1alpha1",
    "kind": "VulnerabilityReport",
    "metadata": {{
        "name": report_name,
        "namespace": "{namespace}",
        "labels": {{
            "grype-operator.security.io/pod": "{pod_name}",
            "grype-operator.security.io/container": "{container_name}"
        }}
    }},
    "spec": {{
        "pod": "{pod_name}",
        "scanTime": datetime.utcnow().isoformat() + "Z",
        "scanner": {{
            "name": "Grype",
            "vendor": "Anchore"
        }},
        "summary": summary,
        "containerReports": [
            {{
                "container": "{container_name}",
                "image": "{escaped_image}",
                "summary": summary,
                "vulnerabilities": vulnerabilities
            }}
        ]
    }}
}}

# Write report to file
with open("/tmp/report.yaml", "w") as f:
    f.write("---\\n")
    f.write("apiVersion: security.grype.io/v1alpha1\\n")
    f.write("kind: VulnerabilityReport\\n")
    f.write("metadata:\\n")
    f.write(f"  name: {report_name}\\n")
    f.write(f"  namespace: {namespace}\\n")
    f.write("  labels:\\n")
    f.write(f"    grype-operator.security.io/pod: {pod_name}\\n")
    f.write(f"    grype-operator.security.io/container: {container_name}\\n")
    f.write("spec:\\n")
    f.write(f"  pod: {pod_name}\\n")
    f.write(f"  scanTime: {{datetime.utcnow().isoformat()}}Z\\n")
    f.write("  scanner:\\n")
    f.write("    name: Grype\\n")
    f.write("    vendor: Anchore\\n")
    f.write("  summary:\\n")
    f.write(f"    critical: {{summary['critical']}}\\n")
    f.write(f"    high: {{summary['high']}}\\n")
    f.write(f"    medium: {{summary['medium']}}\\n")
    f.write(f"    low: {{summary['low']}}\\n")
    f.write(f"    negligible: {{summary['negligible']}}\\n")
    f.write(f"    unknown: {{summary['unknown']}}\\n")
    f.write(f"    total: {{summary['total']}}\\n")
    f.write("  containerReports:\\n")
    f.write("  - container: {container_name}\\n")
    f.write(f"    image: {escaped_image}\\n")
    f.write("    summary:\\n")
    f.write(f"      critical: {{summary['critical']}}\\n")
    f.write(f"      high: {{summary['high']}}\\n")
    f.write(f"      medium: {{summary['medium']}}\\n")
    f.write(f"      low: {{summary['low']}}\\n")
    f.write(f"      negligible: {{summary['negligible']}}\\n")
    f.write(f"      unknown: {{summary['unknown']}}\\n")
    f.write(f"      total: {{summary['total']}}\\n")
    f.write("    vulnerabilities:\\n")
    for vuln in vulnerabilities:
        f.write("    - id: " + vuln['id'] + "\\n")
        f.write("      severity: " + vuln['severity'] + "\\n")
        f.write("      package: " + vuln['package'] + "\\n")
        f.write("      version: " + vuln['version'] + "\\n")
        f.write("      description: " + vuln.get('description', '') + "\\n")

print("VulnerabilityReport YAML generated successfully")

# Apply using kubectl
try:
    result = subprocess.run(
        ["kubectl", "apply", "-f", "/tmp/report.yaml"],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    if result.returncode == 0:
        print("VulnerabilityReport successfully applied!")
        print(result.stdout)
    else:
        print(f"Failed to apply VulnerabilityReport:")
        print(f"STDERR: {{result.stderr}}")
        print(f"STDOUT: {{result.stdout}}")
        # Print the YAML for debugging
        print("Generated YAML:")
        with open("/tmp/report.yaml", "r") as f:
            print(f.read())
        
except Exception as e:
    print(f"Error applying VulnerabilityReport: {{e}}")
    sys.exit(1)

PYTHON_EOF

echo "=== Scan completed successfully ==="
'''
                        ],
                        'env': [
                            {
                                'name': 'GRYPE_CHECK_FOR_APP_UPDATE',
                                'value': 'false'
                            },
                            {
                                'name': 'GRYPE_DB_AUTO_UPDATE',
                                'value': 'true'
                            },
                            {
                                'name': 'GRYPE_DB_CACHE_DIR',
                                'value': '/tmp/grype-db'
                            }
                        ],
                        'resources': {
                            'requests': {
                                'cpu': '500m',
                                'memory': '512Mi'
                            },
                            'limits': {
                                'cpu': '1000m',
                                'memory': '1Gi'
                            }
                        },
                        'volumeMounts': [
                            {
                                'name': 'tmp',
                                'mountPath': '/tmp'
                            }
                        ],
                        'securityContext': {
                            'allowPrivilegeEscalation': False,
                            'runAsNonRoot': False,
                            'runAsUser': 0,
                            'capabilities': {
                                'drop': ['ALL']
                            }
                        }
                    }],
                    'volumes': [
                        {
                            'name': 'tmp',
                            'emptyDir': {}
                        }
                    ],
                    'securityContext': {
                        'fsGroup': 0
                    }
                }
            }
        }
    }
    
    try:
        batch_api.create_namespaced_job(namespace, job)
        logger.info(f"Successfully created scan job: {namespace}/{job_name} for image {image}")
    except kubernetes.client.exceptions.ApiException as e:
        if e.status == 409:
            logger.info(f"Job {namespace}/{job_name} already exists")
        else:
            logger.error(f"Failed to create job {namespace}/{job_name}: {e}")
            logger.error(f"Response body: {e.body}")
    except Exception as e:
        logger.error(f"Unexpected error creating job: {e}")

# Add a probe endpoint for health checks
@kopf.on.probe(id='health')
def health_probe(**kwargs):
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}














# #!/usr/bin/env python3
# """
# Grype Kubernetes Operator
# Creates scanning jobs for container images in Kubernetes workloads
# """

# import kopf
# import kubernetes
# import json
# import logging
# import hashlib
# from datetime import datetime
# from typing import Dict, List, Any

# # Set more verbose logging
# logging.basicConfig(level=logging.DEBUG)
# logger = logging.getLogger(__name__)

# @kopf.on.startup()
# def configure(settings: kopf.OperatorSettings, **_):
#     """Configure operator settings"""
#     settings.persistence.finalizer = 'grype-operator.security.io/finalizer'
#     settings.posting.level = logging.DEBUG
#     settings.watching.server_timeout = 60
#     # Run cluster-wide to avoid the namespace warning
#     settings.watching.clusterwide = True
#     logger.info("Grype Operator starting up...")

# @kopf.on.create('pods')
# @kopf.on.update('pods') 
# def handle_pod(spec, name, namespace, labels, uid, body, **kwargs):
#     """
#     Create scan jobs for pod images when pods are created or updated
#     """
#     logger.info(f"=== HANDLING POD: {namespace}/{name} ===")
#     logger.debug(f"Pod spec: {spec}")
#     logger.debug(f"Pod labels: {labels}")
#     logger.debug(f"Pod annotations: {kwargs.get('annotations', {})}")
    
#     # Skip if already processed (check annotation)
#     annotations = kwargs.get('annotations', {})
#     if annotations.get('grype-operator.security.io/scan-scheduled') == 'true':
#         logger.info(f"Pod {namespace}/{name} already has scan scheduled, skipping")
#         return
    
#     # Skip system namespaces
#     excluded_namespaces = ['kube-system', 'kube-public', 'kube-node-lease', 'grype-operator-system']
#     if namespace in excluded_namespaces:
#         logger.info(f"Skipping system namespace: {namespace}")
#         return
    
#     # Skip scan job pods themselves (prevent infinite recursion)
#     if labels.get('app') == 'grype-scanner':
#         logger.info(f"Skipping scan job pod: {namespace}/{name}")
#         return
    
#     # Skip pods created by jobs (scan jobs)
#     if labels.get('job-name') and 'grype-scan' in labels.get('job-name', ''):
#         logger.info(f"Skipping job pod: {namespace}/{name}")
#         return
    
#     # Skip pods with grype-operator managed labels
#     if labels.get('grype-operator.security.io/managed') == 'true':
#         logger.info(f"Skipping operator-managed pod: {namespace}/{name}")
#         return
    
#     containers = spec.get('containers', [])
#     init_containers = spec.get('initContainers', [])
    
#     all_containers = containers + init_containers
#     logger.info(f"Found {len(all_containers)} containers in pod {namespace}/{name}")
    
#     # Create scan jobs for each unique image
#     scanned_images = set()
#     for container in all_containers:
#         image = container.get('image')
#         container_name = container.get('name')
#         logger.info(f"Processing container: {container_name} with image: {image}")
        
#         if image and image not in scanned_images:
#             logger.info(f"Creating scan job for image: {image} (container: {container_name})")
#             create_scan_job(
#                 namespace=namespace,
#                 pod_name=name,
#                 pod_uid=uid,
#                 container_name=container_name,
#                 image=image
#             )
#             scanned_images.add(image)
#         else:
#             logger.info(f"Skipping image {image} - already scanned or invalid")
    
#     # Annotate pod as scan scheduled
#     if scanned_images:
#         logger.info(f"Annotating pod {namespace}/{name} with scan schedule")
#         api = kubernetes.client.CoreV1Api()
#         patch_body = {
#             "metadata": {
#                 "annotations": {
#                     "grype-operator.security.io/scan-scheduled": "true",
#                     "grype-operator.security.io/schedule-time": datetime.utcnow().isoformat(),
#                     "grype-operator.security.io/images-count": str(len(scanned_images))
#                 }
#             }
#         }
#         try:
#             api.patch_namespaced_pod(name, namespace, patch_body)
#             logger.info(f"Successfully annotated pod {namespace}/{name}")
#         except Exception as e:
#             logger.error(f"Failed to annotate pod {namespace}/{name}: {e}")
#     else:
#         logger.info(f"No images to scan in pod {namespace}/{name}")

# def create_scan_job(namespace: str, pod_name: str, pod_uid: str, 
#                     container_name: str, image: str):
#     """
#     Create a Kubernetes Job to scan the image
#     """
#     logger.info(f"Creating scan job in namespace {namespace} for image {image}")
    
#     batch_api = kubernetes.client.BatchV1Api()
    
#     # Generate unique job name
#     image_hash = hashlib.md5(image.encode()).hexdigest()[:8]
#     job_name = f"grype-scan-{pod_name}-{image_hash}"[:63]
#     report_name = f"{pod_name}-{image_hash}-report"
    
#     # Escape image name for shell
#     escaped_image = image.replace('"', '\\"').replace('$', '\\$')
    
#     # Create job manifest
#     job = {
#         'apiVersion': 'batch/v1',
#         'kind': 'Job',
#         'metadata': {
#             'name': job_name,
#             'namespace': namespace,
#             'labels': {
#                 'app': 'grype-scanner',
#                 'grype-operator.security.io/pod': pod_name,
#                 'grype-operator.security.io/managed': 'true',
#                 'grype-operator.security.io/job': 'true'
#             },
#             'ownerReferences': [{
#                 'apiVersion': 'v1',
#                 'kind': 'Pod',
#                 'name': pod_name,
#                 'uid': pod_uid,
#                 'blockOwnerDeletion': False
#             }]
#         },
#         'spec': {
#             'ttlSecondsAfterFinished': 3600,
#             'backoffLimit': 3,
#             'template': {
#                 'metadata': {
#                     'labels': {
#                         'app': 'grype-scanner',
#                         'grype-operator.security.io/pod': pod_name,
#                         'grype-operator.security.io/managed': 'true',
#                         'grype-operator.security.io/job': 'true'
#                     }
#                 },
#                 'spec': {
#                     'restartPolicy': 'Never',
#                     'serviceAccountName': 'grype-scanner',
#                     'containers': [{
#                         'name': 'grype-scanner',
#                         'image': 'alpine:latest',
#                         'command': ['/bin/sh'],
#                         'args': [
#                             '-c',
#                             f'''#!/bin/sh
# # Install grype using official method
# echo "Installing Grype..."
# apk add --no-cache curl
# curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# echo "=== Starting Grype Scan ==="
# echo "Image: {escaped_image}"
# echo "Pod: {pod_name}, Container: {container_name}"
# echo "Namespace: {namespace}"

# # Update grype database
# echo "Updating Grype database..."
# grype db update || echo "Database update failed, but continuing..."

# # Run grype scan
# echo "Running Grype scan..."
# grype "{escaped_image}" -o json --quiet > /tmp/scan-results.json 2>/tmp/scan-errors.log || {{
#     SCAN_EXIT_CODE=$?
#     echo "Grype scan failed with exit code: $SCAN_EXIT_CODE"
#     echo "Error output:"
#     cat /tmp/scan-errors.log
#     echo "Creating fallback report..."
#     cat > /tmp/scan-results.json << 'FALLBACK_EOF'
# {{
#     "matches": [],
#     "source": {{
#         "target": "{escaped_image}",
#         "type": "image"
#     }},
#     "distro": {{
#         "name": "unknown",
#         "version": "unknown"
#     }},
#     "descriptor": {{
#         "name": "grype",
#         "version": "unknown"
#     }}
# }}
# FALLBACK_EOF
# }}

# echo "Scan completed, processing results..."

# # Install Python for processing
# apk add --no-cache python3

# # Process results with Python
# python3 << 'PYTHON_EOF'
# import json
# import sys
# import os
# from datetime import datetime
# import subprocess

# try:
#     with open("/tmp/scan-results.json", "r") as f:
#         data = json.load(f)
#     print("Successfully loaded scan results")
# except Exception as e:
#     print(f"Error loading scan results: {{e}}")
#     data = {{"matches": []}}

# matches = data.get("matches", [])
# vulnerabilities = []
# summary = {{"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0, "total": 0}}

# for match in matches:
#     vuln = match.get("vulnerability", {{}})
#     artifact = match.get("artifact", {{}})
#     severity = vuln.get("severity", "Unknown").lower()
    
#     vuln_data = {{
#         "id": vuln.get("id", "UNKNOWN"),
#         "severity": vuln.get("severity", "Unknown"),
#         "package": artifact.get("name", "unknown"),
#         "version": artifact.get("version", "unknown"),
#         "fixedVersion": vuln.get("fix", {{}}).get("versions", []),
#         "description": vuln.get("description", "")[:200]
#     }}
#     vulnerabilities.append(vuln_data)
    
#     if severity in summary:
#         summary[severity] += 1
#     else:
#         summary["unknown"] += 1
#     summary["total"] += 1

# print(f"Found {{summary['total']}} vulnerabilities")

# # Create VulnerabilityReport
# report_name = "{report_name}"
# report = {{
#     "apiVersion": "security.grype.io/v1alpha1",
#     "kind": "VulnerabilityReport",
#     "metadata": {{
#         "name": report_name,
#         "namespace": "{namespace}",
#         "labels": {{
#             "grype-operator.security.io/pod": "{pod_name}",
#             "grype-operator.security.io/container": "{container_name}"
#         }}
#     }},
#     "spec": {{
#         "pod": "{pod_name}",
#         "scanTime": datetime.utcnow().isoformat() + "Z",
#         "scanner": {{
#             "name": "Grype",
#             "vendor": "Anchore"
#         }},
#         "summary": summary,
#         "containerReports": [
#             {{
#                 "container": "{container_name}",
#                 "image": "{escaped_image}",
#                 "summary": summary,
#                 "vulnerabilities": vulnerabilities
#             }}
#         ]
#     }}
# }}

# # Write report to file
# with open("/tmp/report.yaml", "w") as f:
#     f.write("---\\n")
#     f.write("apiVersion: security.grype.io/v1alpha1\\n")
#     f.write("kind: VulnerabilityReport\\n")
#     f.write("metadata:\\n")
#     f.write(f"  name: {report_name}\\n")
#     f.write(f"  namespace: {namespace}\\n")
#     f.write("  labels:\\n")
#     f.write(f"    grype-operator.security.io/pod: {pod_name}\\n")
#     f.write(f"    grype-operator.security.io/container: {container_name}\\n")
#     f.write("spec:\\n")
#     f.write(f"  pod: {pod_name}\\n")
#     f.write(f"  scanTime: {{datetime.utcnow().isoformat()}}Z\\n")
#     f.write("  scanner:\\n")
#     f.write("    name: Grype\\n")
#     f.write("    vendor: Anchore\\n")
#     f.write("  summary:\\n")
#     f.write(f"    critical: {{summary['critical']}}\\n")
#     f.write(f"    high: {{summary['high']}}\\n")
#     f.write(f"    medium: {{summary['medium']}}\\n")
#     f.write(f"    low: {{summary['low']}}\\n")
#     f.write(f"    negligible: {{summary['negligible']}}\\n")
#     f.write(f"    unknown: {{summary['unknown']}}\\n")
#     f.write(f"    total: {{summary['total']}}\\n")
#     f.write("  containerReports:\\n")
#     f.write("  - container: {container_name}\\n")
#     f.write(f"    image: {escaped_image}\\n")
#     f.write("    summary:\\n")
#     f.write(f"      critical: {{summary['critical']}}\\n")
#     f.write(f"      high: {{summary['high']}}\\n")
#     f.write(f"      medium: {{summary['medium']}}\\n")
#     f.write(f"      low: {{summary['low']}}\\n")
#     f.write(f"      negligible: {{summary['negligible']}}\\n")
#     f.write(f"      unknown: {{summary['unknown']}}\\n")
#     f.write(f"      total: {{summary['total']}}\\n")
#     f.write("    vulnerabilities:\\n")
#     for vuln in vulnerabilities:
#         f.write("    - id: " + vuln['id'] + "\\n")
#         f.write("      severity: " + vuln['severity'] + "\\n")
#         f.write("      package: " + vuln['package'] + "\\n")
#         f.write("      version: " + vuln['version'] + "\\n")
#         f.write("      description: " + vuln.get('description', '') + "\\n")

# print("VulnerabilityReport YAML generated successfully")

# # Apply using kubectl
# try:
#     result = subprocess.run(
#         ["kubectl", "apply", "-f", "/tmp/report.yaml"],
#         capture_output=True,
#         text=True,
#         timeout=30
#     )
    
#     if result.returncode == 0:
#         print("VulnerabilityReport successfully applied!")
#         print(result.stdout)
#     else:
#         print(f"Failed to apply VulnerabilityReport:")
#         print(f"STDERR: {{result.stderr}}")
#         print(f"STDOUT: {{result.stdout}}")
#         # Print the YAML for debugging
#         print("Generated YAML:")
#         with open("/tmp/report.yaml", "r") as f:
#             print(f.read())
        
# except Exception as e:
#     print(f"Error applying VulnerabilityReport: {{e}}")
#     sys.exit(1)

# PYTHON_EOF

# echo "=== Scan completed successfully ==="
# '''
#                         ],
#                         'env': [
#                             {
#                                 'name': 'GRYPE_CHECK_FOR_APP_UPDATE',
#                                 'value': 'false'
#                             },
#                             {
#                                 'name': 'GRYPE_DB_AUTO_UPDATE',
#                                 'value': 'true'
#                             },
#                             {
#                                 'name': 'GRYPE_DB_CACHE_DIR',
#                                 'value': '/tmp/grype-db'
#                             }
#                         ],
#                         'resources': {
#                             'requests': {
#                                 'cpu': '500m',
#                                 'memory': '512Mi'
#                             },
#                             'limits': {
#                                 'cpu': '1000m',
#                                 'memory': '1Gi'
#                             }
#                         },
#                         'volumeMounts': [
#                             {
#                                 'name': 'tmp',
#                                 'mountPath': '/tmp'
#                             }
#                         ],
#                         'securityContext': {
#                             'allowPrivilegeEscalation': False,
#                             'runAsNonRoot': False,
#                             'runAsUser': 0,
#                             'capabilities': {
#                                 'drop': ['ALL']
#                             }
#                         }
#                     }],
#                     'volumes': [
#                         {
#                             'name': 'tmp',
#                             'emptyDir': {}
#                         }
#                     ],
#                     'securityContext': {
#                         'fsGroup': 0
#                     }
#                 }
#             }
#         }
#     }
    
#     try:
#         batch_api.create_namespaced_job(namespace, job)
#         logger.info(f"Successfully created scan job: {namespace}/{job_name} for image {image}")
#     except kubernetes.client.exceptions.ApiException as e:
#         if e.status == 409:
#             logger.info(f"Job {namespace}/{job_name} already exists")
#         else:
#             logger.error(f"Failed to create job {namespace}/{job_name}: {e}")
#             logger.error(f"Response body: {e.body}")
#     except Exception as e:
#         logger.error(f"Unexpected error creating job: {e}")

# # Add a probe endpoint for health checks
# @kopf.on.probe(id='health')
# def health_probe(**kwargs):
#     return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}