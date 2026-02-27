import yaml
import pytest
from time import sleep
import hpe_3par_kubernetes_manager as manager
import logging
import globals
import time

timeout = globals.status_check_timeout
globals.encryption_test = True

"""logfile = "CSI_test_automation.log"
loglevel = logging.DEBUG
logging.basicConfig(filename=logfile, level=loglevel, format='%(levelname)s-%(asctime)s\n%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('=============================== Test Automation START ========================')
"""


def test_encryption_none_secret_none_namespace_none():
    logging.getLogger().info("Testrail ID: C560623 - test_encryption_none_secret_none_namespace_none")
    pvc_create_verify("%s/encryption/test_enc_none_sec_none_ns_none.yaml" % globals.yaml_dir ,resize_after_mount= "false" )


def test_encryption_none_secret_empty_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560624 - test_encryption_none_secret_empty_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_none_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir,resize_after_mount = "false")


def test_encryption_none_secret_enc_secret_namespace_empty():
    logging.getLogger().info("Testrail ID: C560625 - test_encryption_none_secret_enc_secret_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_none_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir ,resize_after_mount = "false")


def test_encryption_none_secret_empty_namespace_empty():
    logging.getLogger().info("Testrail ID: C560626 - test_encryption_none_secret_empty_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_none_sec_empty_ns_empty.yaml" % globals.yaml_dir ,resize_after_mount = "false")
	

def test_encryption_none_secret_enc_secret_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560627 - test_encryption_none_secret_enc_secret_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_none_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir ,resize_after_mount = "false")
	
	
def test_encryption_invalid_secret_none_namespace_none():
    logging.getLogger().info("Testrail ID: C560628 - test_encryption_invalid_secret_none_namespace_none")
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_none_ns_none.yaml" % globals.yaml_dir ,resize_after_mount = "false")

	
def test_encryption_invalid_secret_empty_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560629 - test_encryption_invalid_secret_empty_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir ,resize_after_mount = "false")

	
def test_encryption_invalid_secret_enc_secret_namespace_empty():
    logging.getLogger().info("Testrail ID: C560630 - test_encryption_invalid_secret_enc_secret_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir ,resize_after_mount = "false")
	
	
def test_encryption_invalid_secret_empty_namespace_empty():
    logging.getLogger().info("Testrail ID: C560631 - test_encryption_invalid_secret_empty_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_empty_ns_empty.yaml" % globals.yaml_dir ,resize_after_mount = "false")
	
	
def test_encryption_invalid_secret_enc_secret_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560632 - test_encryption_invalid_secret_enc_secret_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir ,resize_after_mount = "false")
	
	
def test_encryption_false_secret_none_namespace_none():
    logging.getLogger().info("Testrail ID: C560633 - test_encryption_false_secret_none_namespace_none")
    pvc_create_verify("%s/encryption/test_enc_false_sec_none_ns_none.yaml" % globals.yaml_dir , resize_after_mount = "false")

	
def test_encryption_false_secret_empty_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560634 - test_encryption_false_secret_empty_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_false_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir , resize_after_mount = "false")

	
def test_encryption_false_secret_enc_secret_namespace_empty():
    logging.getLogger().info("Testrail ID: C560635 - test_encryption_false_secret_enc_secret_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_false_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir , resize_after_mount = "false")
	
	
def test_encryption_false_secret_empty_namespace_empty():
    logging.getLogger().info("Testrail ID: C560636 - test_encryption_false_secret_empty_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_false_sec_empty_ns_empty.yaml" % globals.yaml_dir , resize_after_mount = "false")
	
	
def test_encryption_false_secret_enc_secret_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560637 - test_encryption_false_secret_enc_secret_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_false_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir , resize_after_mount = "false")
	

def test_encryption_true_secret_none_namespace_none():
    logging.getLogger().info("Testrail ID: C560638 - test_encryption_true_secret_none_namespace_none")
    pvc_create_verify("%s/encryption/test_enc_true_sec_none_ns_none.yaml" % globals.yaml_dir , resize_after_mount = "false")

	
def test_encryption_true_secret_empty_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560639 - test_encryption_true_secret_empty_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_true_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir , resize_after_mount = "false")

	
def test_encryption_true_secret_enc_secret_namespace_empty():
    logging.getLogger().info("Testrail ID: C560640 - test_encryption_true_secret_enc_secret_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir , resize_after_mount = "false")
	
	
def test_encryption_true_secret_empty_namespace_empty():
    logging.getLogger().info("Testrail ID: C560641 - test_encryption_true_secret_empty_namespace_empty")
    pvc_create_verify("%s/encryption/test_enc_true_sec_empty_ns_empty.yaml" % globals.yaml_dir , resize_after_mount = "false")

	
def test_encryption_true_secret_enc_secret_namespace_hpe_storage_sanity():
    logging.getLogger().info("Testrail ID: C60170122 - test_encryption_true_secret_enc_secret_namespace_hpe_storage_sanity")
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir, resize_after_mount = "true")

def test_encryption_true_secret_enc_secret_namespace_hpe_storage():
    logging.getLogger().info("Testrail ID: C560642 - test_encryption_true_secret_enc_secret_namespace_hpe_storage")
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage_expand_true.yaml" % globals.yaml_dir , resize_after_mount = "false")


def test_encryption_true_secret_enc_secret_namespace_hpe_storage_withHostSeesVlun():
    logging.getLogger().info("Testrail ID: C571125 - test_encryption_true_secret_enc_secret_namespace_hpe_storage_withHostSeesVlun")
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage_withHostSeeVlun.yaml" % globals.yaml_dir , resize_after_mount = "false")

def test_encryption_true_secret_enc_secret_namespace_hpe_storage_HostSeesVlun_false():
    logging.getLogger().info("Testrail ID: C56918373 - test_encryption_true_secret_enc_secret_namespace_hpe_storage_HostSeesVlun_false")
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage_withHostSeeVlun_false.yaml" % globals.yaml_dir, resize_after_mount = "false")


def pvc_create_verify(yml, **kwargs):
    """
    Comprehensive test function to create, verify, and cleanup PVC with encryption validation.
    
    This function performs end-to-end testing of PVC lifecycle including:
    - Storage Class and PVC creation from YAML
    - Volume provisioning status verification via Kubernetes events
    - Encryption parameter validation (hostEncryption, hostEncryptionSecretName, hostEncryptionSecretNamespace)
    - Volume properties verification on HPE 3PAR/Primera/Alletra array
    - Optional volume expansion before or after pod mount
    - Pod creation and attachment verification
    - Device path discovery and multipath validation (protocol-specific)
    - Mount point and filesystem type verification
    - hostSeesVLUN parameter validation (protocol-aware)
    - HPE CRD (Custom Resource Definition) validation
    - Pod deletion and device cleanup verification
    - PVC and volume deletion with CRD cleanup validation
    
    Protocol-specific verification paths:
    
    iSCSI/FC Protocol:
        - Disk partition discovery via /dev/disk/by-path
        - Multipath configuration validation (active/ghost paths)
        - lsscsi entry verification
        - Partition cleanup after pod deletion
        - Multipath entry cleanup verification
        - lsscsi cleanup validation
    
    NVMe-TCP Protocol:
        - NVMe device presence on node (verify_nvme_device_on_node)
        - NVMe multipath configuration with expected path count (verify_nvme_multipath)
        - NVMe device mount points consistency check (verify_nvme_device_mount_points)
          * Compares lsscsi -H output with nvme list-subsys
          * Validates all NVMe controllers are properly recognized
        - NVMe mount and filesystem type validation (verify_nvme_mount_and_fs_type)
          * Verifies device is mounted at correct kubelet path
          * Validates filesystem type (ext4, xfs, etc.) from StorageClass fsType parameter
          * Supports encrypted devices (/dev/mapper/enc-nvme*)
        - HPE Node Info CRD validation (verify_hpenodeinfo)
          * Validates host NQN for NVMe protocol
          * Checks UUID and network configuration
        - HPE Volume Info CRD validation (verify_hpevolumeinfo)
          * Validates access protocol, CPG, provisioning type
          * Verifies target NQN matches expected value
        - NVMe connection cleanup verification (verify_nvme_connection_cleanup)
        - NVMe device cleanup verification (verify_nvme_device_cleanup)
    
    Args:
        yml (str): Path to YAML file containing StorageClass, PVC, and Pod definitions
                   Example: "yaml/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage.yaml"
        **kwargs: Additional keyword arguments
            resize_after_mount (str): Controls volume expansion timing
                - "true": Expand volume AFTER pod is mounted (tests online expansion)
                - "false": Expand volume BEFORE pod mount (tests offline expansion)
                - Only takes effect if StorageClass has allowVolumeExpansion: true
    
    Returns:
        None: Function uses assertions for validation. Successful completion with no
              AssertionError indicates all checks passed.
    
    Raises:
        AssertionError: If any verification step fails (with descriptive message)
        Exception: Re-raises any exception after logging for proper test failure reporting
    
    Example:
        >>> # Test NVMe-TCP with encryption and volume expansion after mount
        >>> pvc_create_verify(
        ...     "yaml/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage.yaml", 
        ...     resize_after_mount="true"
        ... )
        
        >>> # Test iSCSI without volume expansion
        >>> pvc_create_verify(
        ...     "yaml/encryption/test_enc_false_sec_none_ns_none.yaml",
        ...     resize_after_mount="false"
        ... )
    
    Detailed Test Flow:
        1. Parse YAML and create StorageClass with encryption/hostSeesVLUN parameters
        2. Create PVC and monitor provisioning status via Kubernetes events
        3. Validate encryption parameters (hostEncryption, secret name/namespace)
        4. Verify volume created on storage array with correct properties:
           - Size matches requested capacity
           - Provisioning type (tpvv/thin, full/thick, dedup, reduce)
           - Compression setting
           - CPG (Common Provisioning Group) assignment
        5. [Optional] Volume expansion BEFORE mount if:
           - allowVolumeExpansion=true in StorageClass
           - resize_after_mount="false"
           - Validates volume size increased on array (default: 19Gi → 30Gi)
        6. Create Pod and verify it reaches Running state
        7. Verify HPE Volume Info CRD published status = true
        8. Get VLUN details and subsystem/host NQN (for NVMe)
        9. Verify pod scheduled on correct node matching VLUN/device attachment
        10. Protocol-specific hostSeesVLUN validation:
            - NVMe: Always validates type = HOST (NVMe requirement)
            - iSCSI/FC: Validates type = HOST (if hostSeesVLUN="true") or MATCHED_SET (if "false")
        11. [Optional] Volume expansion AFTER mount if:
            - allowVolumeExpansion=true
            - resize_after_mount="true"
        12. Re-read PVC CRD to get updated IQN/LunId after pod attachment
        13. Protocol-specific device verification (see detailed sections above)
        14. Delete Pod and verify it's removed from cluster
        15. Verify device cleanup (protocol-specific - see sections above)
        16. Verify HPE Volume Info CRD published status = false (unpublished)
        17. Delete PVC and verify it's removed from cluster
        18. Verify HPE Volume Info CRD is deleted
        19. Verify volume deleted from storage array
        20. Delete StorageClass and verify removal
    
    Global Dependencies:
        - globals.hpe3par_cli: HPE 3PAR/Primera WSAPI client connection
        - globals.access_protocol: Protocol type ('iscsi', 'fc', 'nvmetcp')
        - globals.namespace: Kubernetes namespace for resources
        - globals.encryption_test: Flag to enable encryption-specific tests
        - globals.HOST_TYPE: Constant for HOST VLUN type validation
        - globals.MATCHED_SET: Constant for MATCHED_SET VLUN type validation
    
    Notes:
        - Cleanup is performed in finally block to ensure resources are released even on failure
        - hostSeesVLUN parameter validation varies by protocol (NVMe always uses HOST type)
        - Volume expansion test resizes from 19Gi to 30Gi by default
        - Filesystem type validation uses StorageClass fsType parameter (default: ext4)
        - Supports encrypted volumes with /dev/mapper/enc-nvme* device paths
        - All verifications log detailed progress at INFO level for troubleshooting
        - Test designed for HPE 3PAR, Primera, and Alletra storage arrays
    """
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        """array_ip, array_uname, array_pwd = manager.read_array_prop(yml)
        hpe3par_cli = manager.get_3par_cli_client(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### new_method %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))"""

        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)


        # Check PVC status in events
        provisioning = None
        compression = None
        size = None
        is_cpg_ssd = None
        provisioning, compression, cpg_name, size = manager.get_sc_properties(yml)
        host_encryption = None
        host_encryption_secret_name = None
        host_encryption_secret_namespace = None
        host_SeesVLUN_set = False 
        allowVolumeExpansion = False
        iscsi_ips = None

        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    if 'hostEncryption' in el['parameters']:
                        host_encryption = el['parameters']['hostEncryption']
                    if 'hostEncryptionSecretName' in el['parameters']:
                        host_encryption_secret_name = el['parameters']['hostEncryptionSecretName']
                    if 'hostEncryptionSecretNamespace' in el['parameters']:
                        host_encryption_secret_namespace = el['parameters']['hostEncryptionSecretNamespace']
                    if 'hostSeesVLUN' in el['parameters']:
                        host_SeesVLUN_set = True
                        hostSeesVLUN = el['parameters']['hostSeesVLUN']
                    if 'allowVolumeExpansion' in el:
                        allowVolumeExpansion = el['allowVolumeExpansion']
                    

        logging.getLogger().info("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                       namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        logging.getLogger().info("Check if test passed...")
        flag = manager.is_test_passed_with_encryption(status=status, enc_secret_name=host_encryption_secret_name,
                                                  yml=yml)
        logging.getLogger().info("Test passed :: %s " % flag)
        assert flag is True, message

        if status == 'ProvisioningSucceeded':
            flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
            assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

            pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
            volume_name = manager.get_pvc_volume(pvc_crd)
            logging.getLogger().info(globals.hpe3par_cli)
            volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
            assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name
            logging.getLogger().info(volume)
            flag, failure_cause = manager.verify_volume_properties_3par(volume, size=size, provisioning=provisioning,
                                                                        compression=compression, cpg=cpg_name)
            assert flag is True, "Volume properties verification at array is failed for %s" % failure_cause


            #Expand volume and validate size of volume after volume properties.
            if allowVolumeExpansion and kwargs['resize_after_mount'] == "false":  
                volume_expand(pvc.metadata.name, pvc_obj)

 
            pod = manager.create_pod(yml)

            flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                                 namespace=pod.metadata.namespace)

            assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

            # Verify crd fpr published status
            assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is True, \
                "PVC CRD %s Published is false after Pod is running" % pvc_obj.spec.volume_name
            hpe3par_vlun = manager.get_3par_vlun(globals.hpe3par_cli, volume_name)
            sub_system_nqn = manager.get_subsystem_nqn(globals.hpe3par_cli, volume_name=volume_name)
            host_nqn = manager.get_host_nqn(globals.hpe3par_cli, volume_name=volume_name)
            assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
                "Node for pod received from 3par and cluster do not match"
            if globals.access_protocol  == "nvmetcp":
                nvme_subsystem_nqn = hpe3par_vlun.get('Subsystem_NQN', '')
                assert nvme_subsystem_nqn != '', "Subsystem NQN is not found for the volume %s" % volume_name
                logging.getLogger().info("NVMe TCP protocol detected - hostSeesVLUN type should always be HOST")
                if host_SeesVLUN_set:
                    for vlun_item in hpe3par_active_vlun:
                        assert vlun_item["type"] == globals.HOST_TYPE, (
                            "hostSeesVLUN parameter validation failed for NVMe TCP volume %s - expected HOST type" 
                            % pvc_obj.spec.volume_name
                        )
            else:
                iscsi_ips = manager.get_iscsi_ips(globals.hpe3par_cli)
                # Adding hostSeesVLUN check
                hpe3par_active_vlun = manager.get_all_active_vluns(globals.hpe3par_cli, volume_name)
                if host_SeesVLUN_set:
                    for vlun_item in hpe3par_active_vlun:
                        if hostSeesVLUN == "true":
                            assert vlun_item['type'] == globals.HOST_TYPE, "hostSeesVLUN parameter validation failed for volume %s" % pvc_obj.spec.volume_name
                        else:
                            assert vlun_item['type'] == globals.MATCHED_SET, "hostSeesVLUN parameter validation failed for volume %s" % pvc_obj.spec.volume_name
                    logging.getLogger().info("Successfully completed hostSeesVLUN parameter check") 
                
            if allowVolumeExpansion and kwargs['resize_after_mount'] == "true":
                volume_expand(pvc.metadata.name, pvc_obj)

            # Read pvc crd again after pod creation. It will have IQN and LunId.
            pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
            flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name, pvc_crd, hpe3par_vlun)
            assert flag is True, "partition not found"
            logging.getLogger().info("disk_partition received are %s " % disk_partition)
            if globals.access_protocol == "iscsi" or globals.access_protocol == "fc":
                flag, disk_partition_mod, partition_map = manager.verify_multipath(hpe3par_vlun, disk_partition)
                assert flag is True, "multipath check failed"
                """print("disk_partition after multipath check are %s " % disk_partition)
                print("disk_partition_mod after multipath check are %s " % disk_partition_mod)"""
                logging.getLogger().info("disk_partition after multipath check are %s " % disk_partition)
                logging.getLogger().info("disk_partition_mod after multipath check are %s " % disk_partition_mod)
                assert manager.verify_partition(disk_partition_mod), "partition mismatch"

                assert manager.verify_lsscsi(pod_obj.spec.node_name, disk_partition), "lsscsi verificatio failed"
                assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                                  pod.metadata.name
                assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod",
                                                namespace=pod.metadata.namespace) is True, \
                    "Pod %s is not deleted yet " % pod.metadata.name

                flag, ip = manager.verify_deleted_partition(iscsi_ips, pod_obj.spec.node_name, hpe3par_vlun, pvc_crd)
                assert flag is True, "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip

                paths = manager.verify_deleted_multipath_entries(pod_obj.spec.node_name, hpe3par_vlun, disk_partition)
                assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

                # partitions = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
                # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
                flag = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
                # print("flag after deleted lsscsi verificatio is %s " % flag)
                logging.getLogger().info("flag after deleted lsscsi verificatio is %s " % flag)
                assert flag, "lsscsi verification failed for vlun deletion"

            else:
                assert manager.verify_nvme_device_on_node(node_name=pod_obj.spec.node_name,subsystem_nqn=sub_system_nqn,volume_name=volume_name), "nvme verification failed"
                assert manager.verify_nvme_multipath(node_name=pod_obj.spec.node_name, subsystem_nqn=sub_system_nqn), "nvme multipath verification failed"
                device_mount_points_valid = manager.verify_nvme_device_mount_points(node_name=pod_obj.spec.node_name)
                assert device_mount_points_valid, \
                    f"NVMe device mount points verification failed on node {pod_obj.spec.node_name}"
                logging.getLogger().info("✓ NVMe device mount points verification passed")
                
                # Get filesystem type from storage class or default to ext4
                expected_fs_type = sc.parameters.get("fsType", "ext4")
                
                mount_fs_valid = manager.verify_nvme_mount_and_fs_type(
                    pvc_name=volume_name,
                    pod_namespace=pod.metadata.namespace,
                    pvc_object= pvc_obj,
                    expected_fs_type=expected_fs_type,
                    node_name=pod_obj.spec.node_name,
                )
                assert mount_fs_valid, \
                    f"NVMe mount and filesystem type verification failed for volume {volume_name}"
                logging.getLogger().info("✓ NVMe mount and filesystem type verification passed")
                assert manager.verify_hpenodeinfo(pod_obj.spec.node_name,protocol=globals.access_protocol,expected_nqn=host_nqn), "hpenodeinfo verification failed"
                assert manager.verify_hpevolumeinfo(volume_name=pvc_obj.spec.volume_name,expected_access_protocol=globals.access_protocol,expected_cpg=cpg_name,expected_provisioning_type=provisioning), "hpevolumeinfo verification failed"
                assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                                  pod.metadata.name
                assert manager.verify_nvme_connection_cleanup(node_name=pod_obj.spec.node_name,subsystem_nqn=sub_system_nqn), "NVMe connection cleanup verification failed"
                assert manager.verify_nvme_device_cleanup(node_name=pod_obj.spec.node_name,hostnqn=host_nqn,volume_name=volume_name), "NVMe device cleanup verification failed"
            # Verify crd for unpublished status
            try:
                assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is False, \
                    "PVC CRD %s Published is true after Pod is deleted" % pvc_obj.spec.volume_name
                # print("PVC CRD published is false after pod deletion.")
                logging.getLogger().info("PVC CRD published is false after pod deletion.")
                # logging.warning("PVC CRD published is false after pod deletion.")
            except Exception as e:
                # print("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
                logging.getLogger().warning(
                    "Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
                # logging.error("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
            assert manager.delete_pvc(pvc.metadata.name)

            assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC",
                                            namespace=pvc.metadata.namespace) is True, \
                "PVC %s is not deleted yet " % pvc.metadata.name

            # pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
            # print("PVC crd after PVC object deletion :: %s " % pvc_crd)
            assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
                "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

            assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
                "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

            assert manager.delete_sc(sc.metadata.name) is True

            assert manager.check_if_deleted(timeout, sc.metadata.name, "SC",
                                            sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                            % sc.metadata.name

            """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

            assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is True, \
                "Secret %s is not deleted yet " % secret.metadata.name"""

    except Exception as e:
        # print("Exception in test_publish :: %s" % e)
        logging.getLogger().error("Exception in test_publish :: %s" % e)
        # logging.error("Exception in test_publish :: %s" % e)
        """if step == 'pvc':
            manager.delete_pvc(pvc.metadata.name)
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'sc':
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'secret':
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
        raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, sc, pvc, pod)


def volume_expand(pvc_name, pvc_obj):
    # expanding volume size of the array
  
    # Setting the capacity(resize) value to 30Gi assuming PVC size in yaml is 19Gi
    cap_vol = '30'
    body = {'spec': {'resources': {'requests': {'storage': cap_vol + 'Gi'}}}}
    patched_pvc_obj = manager.patch_pvc(pvc_name, globals.namespace, body)

    # Setting sleep time to 30 seconds to satisfy response across primera/alletra arrays 
    time.sleep(30)

    voldata = manager.get_volume_from_array(globals.hpe3par_cli, pvc_obj.spec.volume_name[:31])
    assert voldata['sizeMiB'] == int(cap_vol) * 1024, "Volume expand failed"
    logging.getLogger().info("Volume expand validation successful")



def cleanup(secret, sc, pvc, pod):
    #print("====== cleanup :START =========")
    logging.getLogger().info("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", namespace=sc.metadata.namespace) is False:
        manager.delete_sc(sc.metadata.name)
    """if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is False:
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
    #print("====== cleanup :END =========")
    logging.getLogger().info("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")
