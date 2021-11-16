import yaml
import pytest
from time import sleep
import hpe_3par_kubernetes_manager as manager
import logging
import globals

timeout = globals.status_check_timeout
globals.encryption_test = True

"""logfile = "CSI_test_automation.log"
loglevel = logging.DEBUG
logging.basicConfig(filename=logfile, level=loglevel, format='%(levelname)s-%(asctime)s\n%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('=============================== Test Automation START ========================')
"""


def test_encryption_none_secret_none_namespace_none():
    pvc_create_verify("%s/encryption/test_enc_none_sec_none_ns_none.yaml" % globals.yaml_dir)


def test_encryption_none_secret_empty_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_none_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir)


def test_encryption_none_secret_enc_secret_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_none_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir)


def test_encryption_none_secret_empty_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_none_sec_empty_ns_empty.yaml" % globals.yaml_dir)
	

def test_encryption_none_secret_enc_secret_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_none_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir)
	
	
def test_encryption_invalid_secret_none_namespace_none():
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_none_ns_none.yaml" % globals.yaml_dir)

	
def test_encryption_invalid_secret_empty_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir)

	
def test_encryption_invalid_secret_enc_secret_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_invalid_secret_empty_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_empty_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_invalid_secret_enc_secret_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_invalid_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir)	
	
	
def test_encryption_false_secret_none_namespace_none():
    pvc_create_verify("%s/encryption/test_enc_false_sec_none_ns_none.yaml" % globals.yaml_dir)

	
def test_encryption_false_secret_empty_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_false_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir)

	
def test_encryption_false_secret_enc_secret_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_false_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_false_secret_empty_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_false_sec_empty_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_false_secret_enc_secret_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_false_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir)
	

def test_encryption_true_secret_none_namespace_none():
    pvc_create_verify("%s/encryption/test_enc_true_sec_none_ns_none.yaml" % globals.yaml_dir)

	
def test_encryption_true_secret_empty_namespace_hpe_storage():
    pvc_create_verify("%s/encryption/test_enc_true_sec_empty_ns_hpe-storage.yaml" % globals.yaml_dir)

	
def test_encryption_true_secret_enc_secret_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_true_secret_empty_namespace_empty():
    pvc_create_verify("%s/encryption/test_enc_true_sec_empty_ns_empty.yaml" % globals.yaml_dir)
	
	
def test_encryption_true_secret_enc_secret_namespace_hpe_storage_sanity():
    pvc_create_verify("%s/encryption/test_enc_true_sec_enc-sec_ns_hpe-storage.yaml" % globals.yaml_dir)

def pvc_create_verify(yml):
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
            pod = manager.create_pod(yml)

            flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                                 namespace=pod.metadata.namespace)

            assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

            # Verify crd fpr published status
            assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is True, \
                "PVC CRD %s Published is false after Pod is running" % pvc_obj.spec.volume_name

            hpe3par_vlun = manager.get_3par_vlun(globals.hpe3par_cli, volume_name)
            assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
                "Node for pod received from 3par and cluster do not match"

            iscsi_ips = manager.get_iscsi_ips(globals.hpe3par_cli)

            # Read pvc crd again after pod creation. It will have IQN and LunId.
            pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
            flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name, pvc_crd, hpe3par_vlun)
            assert flag is True, "partition not found"
            logging.getLogger().info("disk_partition received are %s " % disk_partition)

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
