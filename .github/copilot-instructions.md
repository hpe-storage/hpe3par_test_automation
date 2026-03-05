# Copilot Instructions - HPE 3PAR Test Automation Framework

## Project Overview
This is an automated test suite for HPE 3PAR/Primera CSI (Container Storage Interface) Driver for Kubernetes and OpenShift platforms. The framework validates storage operations, configurations, and features of the HPE CSI Driver.

## Core Frameworks & Libraries

### Testing Framework
- **pytest**: Primary testing framework
  - Configuration: `pytest.ini`
  - Fixtures and hooks: `conftest.py`
  - Logging: File (`test_automation.log`) and CLI logging enabled
  - Custom markers: `@pytest.mark.csi(version)` for CSI version-based test filtering
  - Command-line options: `--backend`, `--access_protocol`, `--namespace`, `--platform`, `--csi-version`

### Kubernetes Integration
- **kubernetes (Python Client)**: Official Kubernetes Python client
  - APIs used:
    - `client.StorageV1Api()` - Storage classes and volume operations
    - `client.CoreV1Api()` - Pods, PVCs, PVs, Services, Secrets
    - `client.ApiextensionsV1Api()` - Custom Resource Definitions (CRDs)
    - `client.RbacAuthorizationV1Api()` - RBAC resources
    - `client.AppsV1Api()` - Deployments, StatefulSets, DaemonSets
  - Config: `config.load_kube_config()` for cluster authentication
  - Stream API: Used for executing commands in pods

### Storage Array Management
- **hpe3parclient**: HPE 3PAR/Primera Python SDK (REST API client)
  - Package: `hpe3parclient`
  - Class: `HPE3ParClient`
  - Used for direct 3PAR/Primera array operations
  - Exception handling: `HTTPNotFound` and related exceptions
  - Operations: Volume management, CPG operations, host configuration

### SSH/Remote Execution
- **paramiko**: SSH protocol implementation
  - Used for executing commands on Kubernetes/OpenShift nodes
  - Remote operations: Helm commands, node configuration, log collection

### Data Handling
- **PyYAML**: YAML parsing and generation
  - Used for: Kubernetes manifests, configuration files, storage class definitions
  - Files: Secret, PVC, Pod, StorageClass, VolumeSnapshot, VolumeSnapshotClass YAML definitions

### Deployment & Configuration
- **Helm**: Package manager for Kubernetes
  - CSI Driver installation/uninstallation
  - Values files: `values_3par.yaml`, `values.yaml`
  - Namespace: Default is `hpe-storage`

- **Ansible**: Infrastructure automation
  - Playbooks: `csi_csp.yml`, `csi_fix.yml`
  - Inventory: `hosts` file
  - Configuration deployment and setup automation

### Utility Libraries
- **packaging**: Version comparison and parsing
  - Used for CSI version filtering and compatibility checks
- **base64**: Encoding/decoding secrets and credentials
- **logging**: Structured logging throughout the framework
- **json**: JSON data manipulation
- **datetime**: Timestamp operations
- **time/sleep**: Wait operations and timeouts
- **random**: Random value generation for test data
- **ipaddress**: IP address validation and manipulation
- **os**: File system operations
- **re**: Regular expression operations

**All Python dependencies are defined in `requirements.txt`**

## Project Structure

### Core Modules
- **hpe_3par_kubernetes_manager.py**: Main utility module (3145 lines)
  - Kubernetes resource management functions
  - 3PAR array operations wrapper
  - Test helper functions
  - Validation and verification utilities

- **globals.py**: Global configuration variables
  - Runtime configurations: namespace, protocol, platform
  - Test flags: replication_test, encryption_test, newbrand_test
  - Constants: HOST_TYPE, MATCHED_SET, status_check_timeout

- **conftest.py**: Pytest configuration and fixtures (367 lines)
  - Command-line argument parsing
  - Global test setup and teardown
  - Shared fixtures for test modules

### Test Modules
- **test_encryption_3par.py**: Encryption feature tests
- **test_chap.py**: CHAP authentication tests
- **test_iscsi_3par.py**: iSCSI protocol tests
- **test_replicaton.py**: Volume replication tests
- **test_volumeGroup.py**: Volume group operations
- **test_virtual_copy.py**: Virtual copy/snapshot tests
- **test_volume_mutator.py**: Volume mutation webhook tests
- **test_import_vol.py** / **test_import_vol_as_clone.py**: Volume import tests
- **test_helm_install_uninstall.py**: CSI driver deployment tests
- **test_override.py**: Configuration override tests
- **test_multidomain.py**: Multi-domain configuration tests
- **test_new_brand.py**: Rebranding validation tests
- **test_terminating_delete.py**: Resource cleanup tests
- **test_IFDS.py**: IFDS (Intelligent Flash Data Services) tests

### Configuration Files
- **config/config.yaml**: Kubernetes cluster configuration
  - Node IPs, proxy settings, package versions
- **values_3par.yaml** / **values.yaml**: Helm chart values
  - CSI driver images and configurations
  - Backend credentials and settings
  - StorageClass definitions
- **secret.yml** / **enc_secret.yml**: Kubernetes secret manifests
  - Backend authentication credentials
  - Encryption secrets for secure storage
- **requirements.txt**: Python package dependencies
  - All required libraries with version specifications

### YAML Manifests (yaml/ directory)
- Storage Class definitions (compression types: thin, dedup, full, reduce)
- PVC/PV templates
- Pod and Deployment manifests
- VolumeSnapshot and SnapshotClass definitions
- Secret configurations
- Service definitions
- Subdirectories: encryption/, replication/, import_vol/, volume_group/, etc.

## Testing Patterns

### Test Execution
```bash
pytest --backend=<array_ip> --access_protocol=<iscsi|fc> --namespace=<namespace> --platform=<k8s|os>
```

### Common Test Workflow
1. Create Kubernetes resources (StorageClass, PVC, Pod)
2. Verify resource creation and binding
3. Validate storage array operations
4. Perform feature-specific operations (resize, snapshot, clone, etc.)
5. Cleanup resources
6. Verify cleanup completion

### Timeouts & Waits
- Default timeout: `globals.status_check_timeout` (300 seconds)
- Polling intervals: Typically 5-10 seconds
- Background wait times: Based on operation type

### Logging
- Level: INFO (CLI and file)
- Format: `%(asctime)s %(levelname)s %(message)s (%(filename)s:%(lineno)s)`
- TestRail integration: Test case IDs logged for traceability

## Platform Support
- **Kubernetes**: Default platform (`--platform=k8s`)
- **OpenShift**: OpenShift Container Platform (`--platform=os`)

## Protocol Support
- **iSCSI**: Internet Small Computer Systems Interface
- **Fibre Channel (FC)**: High-speed network technology

## Key Features Tested
- Volume provisioning and deletion
- Volume expansion (online and offline)
- Volume cloning and snapshots
- Data encryption at rest
- CHAP authentication
- Volume replication (async/sync)
- Volume groups and consistency groups
- Import existing volumes
- Multi-domain and multi-tenancy
- Resource cleanup and termination handling
- Helm-based CSI driver lifecycle

## Development Guidelines
1. Follow pytest naming conventions (`test_*.py`, `test_*` functions)
2. Use global configuration from `globals.py`
3. Leverage utility functions in `hpe_3par_kubernetes_manager.py`
4. Include TestRail IDs in test docstrings/logs
5. Implement proper cleanup in teardown/finally blocks
6. Use appropriate timeouts for async operations
7. Validate both Kubernetes and 3PAR array states
8. Handle platform-specific differences (k8s vs OpenShift)

## Common Import Pattern
```python
import pytest
import yaml
import logging
import globals
import hpe_3par_kubernetes_manager as manager
from time import sleep
```

## Authentication & Secrets
- Kubernetes secrets for CSI driver authentication
- 3PAR credentials: username/password
- Base64 encoding for sensitive data
- Secret directory: Configurable via `--secret_dir`

## Version Compatibility
- CSI version filtering: `--csi-version` parameter
- Version comparison using `packaging.version`
- Marker-based test selection
- Support for version expressions: `>=2.4.0`, `<=2.5.0`, `==2.4.2`

## CI/CD Integration
- Shell scripts: `setup.sh`, `install_build_ocp.sh`, `email.sh`
- Ansible playbooks for automated deployment
- Log file generation for CI artifacts
- TestRail integration for result tracking

---

## Setup Instructions

### Prerequisites
- Kubernetes cluster (v1.16+) or OpenShift Container Platform
- kubectl/oc CLI tool installed and configured
- Helm 3.x installed
- Python 3.x with pip
- SSH access to cluster nodes
- HPE 3PAR/Primera/Alletra storage array with REST API access

### Environment Setup

#### 1. Install Python Dependencies
Install all required Python packages using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

The requirements file includes all necessary packages:
- pytest - Testing framework
- kubernetes - Kubernetes Python client
- hpe3parclient - HPE 3PAR/Primera Python SDK
- paramiko - SSH client library
- PyYAML - YAML parser
- packaging - Version comparison utilities
- And other utility libraries

#### 2. Configure Array Access
Edit `config/config.yaml` or use command-line arguments:
- Array IP address
- Admin username and password
- Node IPs and hostnames
- Proxy settings (if applicable)
- Access protocol (iSCSI or FC)

#### 3. Kubernetes/OpenShift Setup

**For Kubernetes (K8s):**
```bash
# Install CSI driver using setup.sh
./setup.sh

# Script performs:
# - Fetches latest build from artifactory
# - Clones co-deployments repository
# - Downloads CSI controller and node YAMLs
# - Uninstalls existing driver (if present)
# - Cleans up CRDs (hpenodeinfos, hpevolumeinfos, volumegroups, etc.)
# - Installs snapshot CRDs (external-snapshotter v4.1)
# - Installs HPE CSI driver via Helm
```

**For OpenShift (OS):**
```bash
# Install CSI driver using install_build_ocp.sh
./install_build_ocp.sh

# Script performs:
# - Fetches latest build from artifactory
# - Clones co-deployments repository
# - Downloads operator YAML and CRDs
# - Cleans up existing CSI resources
# - Installs snapshot CRDs
# - Creates SCC, roles, service accounts
# - Installs HPE CSI operator
# - Deploys HPE CSI driver CR
```

#### 4. Configure Test Parameters

**Edit values_3par.yaml:**
```yaml
secret:
  backend: <array_ip>
  username: <array_username>
  password: <array_password>
  servicePort: "8080" or "443"

images:
  csiDriverImage: hpestorage/csi-driver:<version>
  cspImage: <csp_image>:<tag>

backendType: primera3par
flavor: kubernetes  # or openshift
```

#### 5. Run Tests

**Basic test execution:**
```bash
pytest --backend=<array_ip> \
       --access_protocol=<iscsi|fc> \
       --namespace=hpe-storage \
       --platform=k8s \
       --username=<array_user> \
       --password=<array_pass>
```

**Run specific test module:**
```bash
pytest test_encryption_3par.py --backend=<array_ip> --access_protocol=iscsi
```

**Run with CSI version filter:**
```bash
pytest --csi-version=">=2.4.0" --backend=<array_ip> --access_protocol=iscsi
```

**Run specific test:**
```bash
pytest test_encryption_3par.py::test_encryption_true_secret_empty_namespace_hpe_storage
```

### Directory Structure Setup
```
hpe3par_test_automation/
├── config/
│   └── config.yaml          # Cluster and node configuration
├── yaml/                     # K8s manifest templates
│   ├── encryption/          # Encryption test manifests
│   ├── replication/         # Replication test manifests
│   ├── volume_group/        # Volume group test manifests
│   └── ...
├── test_*.py                # Test modules
├── conftest.py              # Pytest fixtures and configuration
├── globals.py               # Global variables
├── hpe_3par_kubernetes_manager.py  # Core utility functions
├── pytest.ini               # Pytest configuration
├── requirements.txt         # Python package dependencies
├── setup.sh                 # K8s CSI driver installation
└── install_build_ocp.sh    # OpenShift CSI driver installation
```

---

## Framework Architecture

### Architectural Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Layer (test_*.py)                    │
│  - Test cases implementing specific feature validations      │
│  - Uses pytest fixtures and markers                          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              Test Orchestration (conftest.py)                │
│  - Pytest configuration and hooks                            │
│  - Session-level fixtures (array connection, secrets)        │
│  - Command-line argument parsing                             │
│  - Global test setup and teardown                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│           Utility Layer (hpe_3par_kubernetes_manager.py)     │
│  - Kubernetes resource management                            │
│  - 3PAR/Primera array operations                             │
│  - SSH/remote command execution                              │
│  - Verification and validation functions                     │
│  - Resource creation, deletion, status checks                │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────┬──────────────────────────────────────┐
│  Kubernetes API      │     HPE 3PAR/Primera Array           │
│  - Storage APIs      │     - REST API (hpe3parclient)       │
│  - Core APIs         │     - Volume operations              │
│  - RBAC APIs         │     - CPG management                 │
│  - Apps APIs         │     - Host/VLUN operations           │
└──────────────────────┴──────────────────────────────────────┘
```

### Component Interaction Flow

**1. Test Initialization:**
```
pytest → conftest.py → pytest_configure()
                    → pytest_addoption() (parse CLI args)
                    → secret() fixture (connect to array)
                    → globals.py (set runtime variables)
```

**2. Test Execution Flow:**
```
Test Function
    ↓
Load YAML manifest (from yaml/ directory)
    ↓
Create K8s resources (SC, PVC, Pod) via manager functions
    ↓
Verify K8s resource status (check_status, check_if_deleted)
    ↓
Verify array operations (verify_volume_properties, verify_host_properties)
    ↓
Perform test-specific operations (resize, snapshot, clone, etc.)
    ↓
Verify operation success (verification functions)
    ↓
Cleanup resources (delete functions)
    ↓
Verify cleanup (check_if_deleted)
```

**3. Resource Management Pattern:**
```
hpe_create_*_object(yml) → K8s API call → Resource created
                        ↓
            check_status(timeout, name, kind, status)
                        ↓
            Polling loop (wait for desired state)
                        ↓
            verify_*_properties(**kwargs)
                        ↓
            Assertions (validate expected state)
```

### Key Architectural Components

#### 1. **conftest.py - Test Orchestration**
- **Responsibilities:**
  - Parse command-line arguments
  - Initialize array connection
  - Create session-level fixtures
  - Configure global variables
  - Handle CSI version filtering

- **Key Functions:**
  - `pytest_addoption()`: Define CLI arguments
  - `pytest_configure()`: Setup test environment
  - `secret()`: Session fixture for array connection
  - `encodePwd()`: Password encoding utility

#### 2. **hpe_3par_kubernetes_manager.py - Core Utility**
- **Responsibilities:**
  - Abstract Kubernetes API interactions
  - Handle 3PAR/Primera array operations
  - Execute remote SSH commands
  - Implement verification logic
  - Manage resource lifecycle

- **Function Categories:**
  - **Creation:** `hpe_create_*_object()` - Create K8s resources
  - **Deletion:** `hpe_delete_*_object()` - Delete K8s resources
  - **Status Checking:** `check_status()`, `check_if_deleted()`
  - **Verification:** `verify_*_properties()`, `verify_*_created()`
  - **Array Operations:** `get_3par_cli_client()`, `get_volume_from_array()`
  - **SSH Operations:** `get_command_output()` - Execute remote commands

#### 3. **globals.py - Shared State**
- **Purpose:** Central configuration store
- **Variables:**
  - Runtime: `namespace`, `yaml_dir`, `platform`, `access_protocol`
  - Test flags: `encryption_test`, `replication_test`, `newbrand_test`
  - Array info: `hpe3par_cli`, `hpe3par_version`, `hpe3par_model`
  - Constants: `status_check_timeout`, `HOST_TYPE`, `MATCHED_SET`

#### 4. **Test Modules - Feature Validation**
- **Structure:**
  - Import utilities and globals
  - Define test functions (test_*)
  - Use YAML manifests from yaml/ directory
  - Implement test-specific logic
  - Include cleanup in finally blocks

- **Common Pattern:**
```python
def test_feature():
    try:
        # Create resources
        sc = manager.hpe_create_sc_object(yml)
        pvc = manager.hpe_create_pvc_object(yml)
        
        # Verify creation
        assert manager.check_status(timeout, pvc_name, "PVC", "Bound")
        
        # Verify array state
        volume = manager.get_volume_from_array(hpe3par_cli, volume_name)
        assert manager.verify_volume_properties(volume, **kwargs)
        
        # Perform operations
        # ... test-specific logic ...
        
    finally:
        # Cleanup
        manager.delete_pvc(pvc_name)
        manager.delete_sc(sc_name)
```

### Data Flow Architecture

**Test Data → YAML Manifests → K8s Resources → Storage Array**

1. **YAML Templates:** Pre-defined manifests in yaml/ directory
2. **Dynamic Generation:** Runtime substitution of variables
3. **K8s API:** Resources created via Python Kubernetes client
4. **CSI Driver:** Translates K8s requests to array operations
5. **Verification:** Dual validation (K8s state + array state)

### Error Handling Strategy

```
Try-Except-Finally Pattern:
├── Try: Main test logic
├── Except: Catch and log exceptions
└── Finally: Guaranteed cleanup
    ├── Delete K8s resources
    ├── Verify deletion
    └── Clean array artifacts (if needed)
```

### Timeout and Polling Mechanism

```python
# Common timeout pattern
def check_status(timeout, name, kind, status, namespace):
    elapsed_time = 0
    while elapsed_time < timeout:
        resource = get_resource(name)
        if resource.status == status:
            return True
        sleep(5)
        elapsed_time += 5
    return False
```

### Logging Architecture

**Multi-level logging:**
- **CLI Output:** Real-time test progress (INFO level)
- **File Output:** Detailed logs in `test_automation.log`
- **Format:** `%(asctime)s %(levelname)s %(message)s (%(filename)s:%(lineno)s)`
- **Integration:** TestRail IDs included for traceability

---

## Verification Steps

The framework implements comprehensive verification at multiple levels to ensure correctness of CSI driver operations.

### 1. Kubernetes Resource Verification

#### PVC Verification
```python
# Check PVC status
check_status(timeout, pvc_name, "PVC", "Bound", namespace)

# Verify PVC properties
- Binding status (Bound/Pending)
- Capacity matches requested size
- Storage class association
- Volume name assignment
- Access modes
```

#### Pod Verification
```python
# Check Pod status
check_status(timeout, pod_name, "Pod", "Running", namespace)

# Verify Pod properties
- Running state
- Volume mount successful
- Node placement (for affinity tests)
- Container readiness
```

#### Storage Class Verification
```python
# Verify storage class created
verify_sc_exists(sc_name)

# Check properties
- Provisioner: csi.hpe.com
- Parameters (cpg, provisioning type, compression)
- Reclaim policy
- Volume binding mode
```

### 2. Array-Level Verification

#### Volume Properties Verification
```python
verify_volume_properties_3par(hpe3par_volume, **kwargs)

# Verifies:
- Provisioning Type:
  * Full (provisioningType == 1)
  * Thin/TPVV (provisioningType == 2)
  * Dedup/TDVV (provisioningType == 6, deduplicationState == 1)
  
- Size: sizeMiB matches requested size (in GiB * 1024)

- Compression State:
  * Enabled: compressionState in [1,5,6] or -1
  * Disabled: compressionState == 2
  * Not applicable (full): compressionState == 4
  
- CPG Assignment: userCPG matches specified CPG
- Snap CPG: snapCPG matches (if specified)
- Clone Properties: copyType, copyOf parent
```

#### Host Properties Verification
```python
verify_host_properties(hpe3par_host, **kwargs)

# Verifies:
- CHAP Authentication:
  * initiatorChapEnabled == True
  * initiatorChapName matches chapUser
  * Decrypted initiatorEncryptedChapSecret matches chapPassword
  
- Initiator Registration:
  * IQN or WWN properly registered
  * Host persona correct
  * FC/iSCSI paths configured
```

#### VLUN (Volume Export) Verification
```python
verify_pod_node(hpe3par_vlun, pod)

# Verifies:
- Volume exported to correct host
- LUN ID assigned
- Host name matches node
- Multipath configuration (if applicable)
```

### 3. Node-Level Verification (iSCSI)

#### Multipath Verification
```python
verify_multipath(hpe3par_vlun, disk_partition)

# Checks:
- Multipath device created
- All paths active
- Path count matches array configuration
- Device mapper entry exists
- Correct path selection policy
```

#### iSCSI Session Verification
```python
verify_by_path(iscsi_ips, node_name, pvc_crd, hpe3par_vlun)

# Verifies:
- iSCSI sessions established to all target IPs
- Sessions in "running" state
- Target portal groups correct
- Initiator name matches host registration
```

#### Block Device Verification
```python
verify_lsscsi(node_name, disk_partition)

# Checks:
- SCSI device detected
- Correct vendor (3PARdata)
- Device path exists
- Serial number matches volume

verify_partition(disk_partition)
# Confirms partition exists in /dev/
```

### 4. Snapshot and Clone Verification

#### Snapshot Verification
```python
verify_snapshot_created(snapshot_name)
# Checks VolumeSnapshot resource created

verify_snapshot_ready(snapshot_name)
# Checks readyToUse = True

verify_snapshot_on_3par(hpe3par_volume, volume_name)
# Verifies:
- Snapshot exists on array
- Parent-child relationship correct
- Snapshot name follows convention
- Snapshot properties match
```

#### Clone Verification
```python
verify_clone_crd_status(pvc_volume_name)
# Checks HPEVolumeInfo CRD for clone status

verify_volume_properties(clone_volume, clone=True, copyOf=parent_volume)
# Verifies:
- copyType == 1 (physical copy)
- copyOf points to parent volume
- Size matches parent
- CPG/snapCPG configuration
```

### 5. CRD (Custom Resource Definition) Verification

#### HPEVolumeInfo CRD
```python
verify_crd_exists(crd_name, crd_type='hpevolumeinfos')

# Verifies:
- CRD exists for PVC
- Volume ID matches array volume
- Record fields populated correctly
- Status reflects current state
```

#### HPENodeInfo CRD
```python
verify_node_crd_chap(crd_name, chapUser=user, chapPassword=pwd)

# Verifies:
- CHAP credentials stored correctly
- Base64 encoded password matches
- Node IQN/WWN recorded
- Array UUID correct
```

#### Published Status
```python
verify_pvc_crd_published(crd_name)
# Checks CRD shows volume published to node
```

### 6. Cleanup Verification

#### Resource Deletion Verification
```python
check_if_deleted(timeout, name, kind, namespace)

# Verifies resource deleted within timeout:
- PVC removed from K8s
- Pod terminated and removed
- Service deleted
- Secret removed
- Storage class deleted (if created by test)
```

#### Array Cleanup Verification
```python
verify_delete_volume_on_3par(hpe3par_cli, volume_name)
# Confirms volume deleted from array
# Expects HTTPNotFound exception

verify_deleted_partition(iscsi_ips, node_name, hpe3par_vlun, pvc_crd)
# Verifies iSCSI sessions closed and devices removed

verify_deleted_multipath_entries(node_name, hpe3par_vlun, disk_partition)
# Confirms multipath devices cleaned up

verify_deleted_lsscsi_entries(node_name, disk_partition)
# Verifies SCSI devices removed from node
```

### 7. Event-Based Verification

```python
check_event(kind, name)
# Checks K8s events for resource
# Useful for debugging failures

check_status_from_events(kind, name, namespace, uid, reasons=[...])
# Polls events for specific reasons:
- ProvisioningSucceeded
- ProvisioningFailed
- VolumeResizeSucceeded
- VolumeResizeFailed
```

### 8. Replication Verification

```python
check_if_rcg_exists(rcg_name, hpe3par_cli)
# Verifies Remote Copy Group exists on array

# Replication volume checks:
- rcopyStatus indicates replication active
- Remote volume exists on target array
- Sync status appropriate (synced/syncing/failed)
```

### 9. Volume Expansion Verification

```python
# After expansion request:
1. Check PVC status reflects new size
2. Verify volume size on array updated
3. Confirm filesystem resized (if online expansion)
4. Check events for ResizeSucceeded
```

### 10. Multi-Domain Verification

```python
check_cpg_prop_at_array(hpe3par_cli, cpg_name, property)
# Verifies CPG properties match domain restrictions

# Domain-specific checks:
- Volume created in correct CPG
- CPG belongs to expected domain
- Domain permissions enforced
```

### Verification Best Practices

1. **Dual Verification:** Always verify both Kubernetes state and array state
2. **Timeout Handling:** Use appropriate timeouts (globals.status_check_timeout)
3. **Polling:** Implement polling for async operations
4. **Cleanup Verification:** Ensure resources fully removed before test ends
5. **Error Context:** Log verification failures with detailed context
6. **Node-Level Checks:** For iSCSI, verify device attachment on nodes
7. **Event Monitoring:** Check K8s events for detailed operation status
8. **CRD Validation:** Verify CSI driver CRDs reflect correct state

### Common Verification Patterns

```python
# Pattern 1: Create and Verify
resource = create_resource(yml)
assert check_status(timeout, name, kind, "Ready")
assert verify_properties(resource, **expected)

# Pattern 2: Operation and Verify
perform_operation()
assert check_status(timeout, name, kind, "Expected_State")
array_resource = get_from_array(name)
assert verify_array_state(array_resource)

# Pattern 3: Delete and Verify
delete_resource(name)
assert check_if_deleted(timeout, name, kind)
assert verify_delete_on_array(cli, name)  # Should raise HTTPNotFound
```
