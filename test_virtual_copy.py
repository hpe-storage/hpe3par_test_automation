import hpe_3par_kubernetes_manager as manager
from hpe3parclient.exceptions import HTTPBadRequest
from hpe3parclient.exceptions import HTTPForbidden
from hpe3parclient.exceptions import HTTPConflict
from hpe3parclient.exceptions import HTTPNotFound
import time
import yaml
import pytest

import globals 
import logging


timeout = 900


def test_virtual_copyOf_tpvv_vol():
    base_yml = '%s/virtual-copy/virtual-copy-base-vol.yml' % globals.yaml_dir
    snap_yml = '%s/virtual-copy/virtual-copy-snap-vol.yml' % globals.yaml_dir
    test_virtual_copyOf(base_yml,snap_yml)

@pytest.mark.skip_array("3par")
def test_virtual_copyOf_reduce_vol():
    base_yml = '%s/virtual-copy/virtual-copy-base-vol-tc2.yml' % globals.yaml_dir
    snap_yml = '%s/virtual-copy/virtual-copy-snap-vol-tc2.yml' % globals.yaml_dir
    test_virtual_copyOf(base_yml,snap_yml)

@pytest.mark.skip_array("primera")
def test_virtual_copyOf_tdvv_vol():
    base_yml = '%s/virtual-copy/virtual-copy-base-vol-tc3.yml' % globals.yaml_dir
    snap_yml = '%s/virtual-copy/virtual-copy-snap-vol-tc3.yml' % globals.yaml_dir
    test_virtual_copyOf(base_yml,snap_yml)

#@pytest.mark.skip_array("primera")
def test_virtual_copyOf_tdvv_compr_vol():
    base_yml = '%s/virtual-copy/virtual-copy-base-vol-tc4.yml' % globals.yaml_dir
    snap_yml = '%s/virtual-copy/virtual-copy-snap-vol-tc4.yml' % globals.yaml_dir
    test_virtual_copyOf(base_yml,snap_yml)



def test_virtual_copyOf(base_yml,snap_yml):
    #base_yml = '%s/virtual-copy/virtual-copy-base-vol.yml' % globals.yaml_dir
    #snap_yml = '%s/virtual-copy/virtual-copy-snap-vol.yml' % globals.yaml_dir
    pvc_snap = None
    sc_snap = None
    snap_pod = None
    sc = None
    pvc = None
    pod = None
    isPresent = False
    isValid = False
    try:
        with open(base_yml, "r") as ymlfile:
             elements = list(yaml.safe_load_all(ymlfile))
             for el in elements:
                 if str(el.get('kind')) == "StorageClass":
                     cpg = el['parameters']['cpg']
                     snapCPG = el['parameters']['snapCpg']
                     provisioningType = el['parameters']['provisioning_type']
                     compression = el['parameters']['compression']
                     break

        #array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        # Creating base volume now in CSI
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        time.sleep(20)
        
        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export'] 
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mydata.txt" in x for x in data.split('\n')):
            isPresent = True
        assert isPresent is True, "File not present in base volume"
            

        # Creating snap volume in CSI
        sc_snap = manager.create_sc(snap_yml)
        pvc_snap = manager.create_pvc(snap_yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, snap_pvc_obj = manager.check_status(30, pvc_snap.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc_snap.metadata.namespace)
        assert flag is True, "Snapshot PVC %s status check timed out, not in Bound state yet..." % snap_pvc_obj.metadata.name
  
        #Export snapshot volume
        snap_pod = manager.create_pod(snap_yml)
        flag, snap_pod_obj = manager.check_status(timeout, snap_pod.metadata.name, kind='pod', status='Running',
                                             namespace=snap_pod.metadata.namespace)
        assert flag is True, "Snapshot volume pod mount %s status check timed out, not in Running state yet..." % snap_pod.metadata.name
        logging.getLogger().info("Checking snapshot volume data")
        time.sleep(20)

        # Validating data on snapshot volume 
        isPresent = False
        command = ['/bin/sh', '-c', 'ls -l /export']
        snap_data = manager.hpe_connect_pod_container(snap_pod.metadata.name, command)
        if any("mydata.txt" in x for x in snap_data.split('\n')):
            isPresent = True
        assert isPresent is True, "File on base volume not found in snap volume"

        isPresent = False
        if any("mysnapdata.txt" in x for x in snap_data.split('\n')):
            isPresent = True
        assert isPresent is True, "File not present in snap volume"
        logging.getLogger().info("snapshot volume data check successfull")
        time.sleep(10)

        #Validate snapshot pvc crd
        pvc_crd = manager.get_pvc_crd("pvc-"+snap_pvc_obj.metadata.uid)
        assert pvc_crd['spec']['record']['BaseSnapshotId'] == "pvc-"+snap_pvc_obj.metadata.uid, "Base snapshot id is incorrect %s" %  pvc_crd['spec']['record']['BaseSnapshotId']
        assert pvc_crd['spec']['record']['ParentVolumeId'] == "pvc-"+base_pvc_obj.metadata.uid, "Parent id is incorrect %s" %  pvc_crd['spec']['record']['ParentVolumeId']
        logging.getLogger().info("Volume crd check successfull")

        #Validating base volume properties
        #hpe3par_cli = manager.get_3par_cli_client(base_yml)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, pvc_crd['spec']['record']['ParentBackendName'])
        isValid = manager.verify_volume_properties(base_volume, cpg = cpg, provisioning = provisioningType, compression = compression)
        assert isValid is True, "Validation of base volume failed"
        logging.getLogger().info("base volume check on the array successfull")


        #Validating snapshot volume properties 
        #hpe3par_cli = manager.get_3par_cli_client(snap_yml) 
        snap_volume = manager.get_volume_from_array(globals.hpe3par_cli, pvc_crd['spec']['record']['Name'])
        
        isValid = manager.verify_volume_properties(snap_volume , name = pvc_crd['spec']['record']['Name'], copyOf = pvc_crd['spec']['record']['ParentBackendName'], snapCPG = snapCPG)
        assert isValid is True, "Validation of snapshot volume failed"
        logging.getLogger().info("snapshot volume check on the array successfull")
        time.sleep(20)
        

        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(snap_pod.metadata.name, snap_pod.metadata.namespace)
        flag = manager.check_if_deleted(180, snap_pod.metadata.name, "Pod", namespace=snap_pod.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % snap_pod.metadata.name

        manager.delete_pvc(snap_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, snap_pvc_obj.metadata.name, "PVC", namespace=snap_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % snap_pvc_obj.metadata.name

        manager.delete_sc(sc_snap.metadata.name)
        flag =  manager.check_if_deleted(2, sc_snap.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc_snap.metadata.name

        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name

        manager.delete_pvc(base_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, base_pvc_obj.metadata.name, "Pod", namespace=base_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % base_pvc_obj.metadata.name

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name
        #manager.delete_secret(secret.metadata.name, secret.metadata.namespace)

 
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc_snap, pvc_snap, snap_pod)
        cleanup(sc, pvc, pod)


'''def test_virtual_copyOf_tdvv_vol():
    base_yml = 'YAML/virtual-copy/virtual-copy-base-vol-tc2.yml'
    snap_yml = 'YAML/virtual-copy/virtual-copy-snap-vol-tc2.yml'
    hpe3par_cli = None
    snap_pvc = None
    clone_pod_obj = None
    timeout = 900
    secret = None
    sc = None
    pvc = None
    pod = None
    isPresent = False
    isValid = False
    try:
        with open('YAML/virtual-copy/testcase2_base_sc.yml', "r") as ymlfile:
            cfg = yaml.load(ymlfile)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        # Creating base volume now in CSI
        secret = manager.create_secret(base_yml)
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        print("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        try:
            # Export base volume
            base_pod = manager.create_pod(base_yml)
            flag, base_pod_obj = manager.check_status(timeout, base_pod.metadata.name, kind='pod', status='Running',
                                             namespace=base_pod.metadata.namespace)
            assert flag is True, "Pod %s status check timed out, not in Running state yet..." % base_pod.metadata.name

            # Checking base volume data
            command = ['/bin/sh', '-c', 'ls -l /export']
            data = manager.hpe_connect_pod_container(base_pod.metadata.name, command)
            if any("mydata.txt" in x for x in data.split('\n')):
                isPresent = True
            assert isPresent is True, "File not present in base volume"
            time.sleep(20)
        except Exception as e:
            cleanup(secret,sc,pvc,base_pod)
            raise e         


        # Creating snap volume in CSI
        sc_snap = manager.create_sc(snap_yml)
        pvc_snap = manager.create_pvc(snap_yml)
        print("Check in events if volume is created...")
        flag, snap_pvc_obj = manager.check_status(30, pvc_snap.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc_snap.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % snap_pvc_obj.metadata.name

        try:    
            #Export snapshot volume
            snap_pod = manager.create_pod(snap_yml)
            flag, snap_pod_obj = manager.check_status(timeout, snap_pod.metadata.name, kind='pod', status='Running',
                                             namespace=snap_pod.metadata.namespace)
            assert flag is True, "Pod %s status check timed out, not in Running state yet..." % snap_pod.metadata.name

            # Validating data on snapshot volume
            isPresent = False
            command = ['/bin/sh', '-c', 'ls -l /export']
            snap_data = manager.hpe_connect_pod_container(snap_pod.metadata.name, command)
            if any("mydata.txt" in x for x in snap_data.split('\n')):
                isPresent = True
            assert isPresent is True, "File on base volume not found in snap volume"

            isPresent = False
            if any("mysnapdata.txt" in x for x in snap_data.split('\n')):
                isPresent = True
            assert isPresent is True, "File not present in snap volume"

        except Exception as e:
            cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
            cleanup(secret, sc, base_pvc_obj, base_pod_obj)
            raise e    


        #Validate snapshot pvc crd
        pvc_crd = manager.get_pvc_crd("pvc-"+snap_pvc_obj.metadata.uid)
        assert pvc_crd['spec']['record']['BaseSnapshotId'] == "pvc-"+snap_pvc_obj.metadata.uid, "Base snapshot id is incorrect %s" %  pvc_crd['spec']['record']['BaseSnapshotId']
        assert pvc_crd['spec']['record']['ParentVolumeId'] == "pvc-"+base_pvc_obj.metadata.uid, "Parent id is incorrect %s" %  pvc_crd['spec']['record']['ParentVolumeId']

        #Validating base volume properties
        hpe3par_cli = manager.get_3par_cli_client(base_yml)
        base_volume = manager.get_volume_from_array(hpe3par_cli, pvc_crd['spec']['record']['ParentBackendName'])
        isValid = manager.verify_volume_properties_primera(base_volume , cpg = cfg['parameters']['cpg'], provisioning = 'dedup')
        assert isValid is True, "Validation of snapshot volume failed"


        #Validating snapshot volume properties
        #hpe3par_cli = manager.get_3par_cli_client(snap_yml)
        snap_volume = manager.get_volume_from_array(hpe3par_cli, pvc_crd['spec']['record']['Name'])
        isValid = manager.verify_volume_properties(snap_volume , name = pvc_crd['spec']['record']['Name'], copyOf = pvc_crd['spec']['record']['ParentBackendName'])
        assert isValid is True, "Validation of snapshot volume failed"

        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(snap_pod.metadata.name, snap_pod.metadata.namespace)
        flag = manager.check_if_deleted(180, snap_pod.metadata.name, "Pod", namespace=snap_pod.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % snap_pod.metadata.name

        manager.delete_pvc(snap_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, snap_pvc_obj.metadata.name, "PVC", namespace=snap_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % snap_pvc_obj.metadata.name

        manager.delete_sc(sc_snap.metadata.name)
        flag =  manager.check_if_deleted(2, sc_snap.metadata.name, "SC")
        assert flag is True, "SC %s delete status check timedout..." % sc_snap.metadata.name

        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name

        manager.delete_pvc(base_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, base_pvc_obj.metadata.name, "Pod", namespace=base_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % base_pvc_obj.metadata.name

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC")
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)


    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(secret, sc, base_pvc_obj, base_pod_obj)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()'''


def cleanup(sc, pvc, pod):
    print("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", None) is False:
        manager.delete_sc(sc.metadata.name)
    print("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")

