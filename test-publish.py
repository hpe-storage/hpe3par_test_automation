import hpe_3par_kubernetes_manager as manager
import yaml
from time import sleep
import base64
import pytest

encoding = "utf-8"
objects = {}
timeout = 1000
HPE3PAR_IP = None
HPE3PAR_USERNAME = None
HPE3PAR_PWD = None
HPE3PAR_API_URL = None

hpe3par_cli = None

# for vlun verification
iscsi_ips = []
disk_partitions_by_ip = {}
disk_partition = []
disk_partition_temp = []


def test_create_objects():
    print("\n########################### test_create_objects ###########################")
    try:
        # Create PV, PVC and Pod
        yml = "YAML/test-publish.yml"
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    # print("PersistentVolume YAML :: %s" % el)
                    print("\nCreating StorageClass...")
                    sc_name = manager.hpe_create_sc_object(el).metadata.name
                    print("\nStorageClass %s created." % sc_name)
                    objects["SC"] = str(sc_name)
                if str(el.get('kind')) == "PersistentVolumeClaim":
                    print("\nCreating PVC...")
                    pvc_obj = manager.hpe_create_pvc_object(el)
                    pvc_name = pvc_obj.metadata.name
                    print("\nPersistentVolumeClaim %s created." % pvc_name)
                    pvc_map = {'name': str(pvc_name), 'namespace': pvc_obj.metadata.namespace}
                    """pvc_map['name'] = str(pvc_name)
                    pvc_map['namespace'] = el.get('metadata')['namespace']"""
                    objects["PVC"] = pvc_map
                if str(el.get('kind')) == "Secret":
                    print("\nCreating Secret...")
                    secret_obj = manager.hpe_create_secret_object(el)
                    secret_name = secret_obj.metadata.name
                    print("\nSecret %s created." % secret_name)
                    secret_map = {'name': str(secret_name), 'namespace': secret_obj.metadata.namespace}
                    objects["Secret"] = secret_map
                if str(el.get('kind')) == "Pod":
                    print("\nCreating Pod...")
                    pod_obj = manager.hpe_create_pod_object(el)
                    pod_name = pod_obj.metadata.name
                    print("\nPod %s created." % pod_name)
                    pod_map = {'name': str(pod_name), 'namespace': pod_obj.metadata.namespace}
                    objects["Pod"] = pod_map
    except Exception as e:
        print("Exception while creating objects :: %s" % e)
        raise e


def test_verify_pvc_pod_status():
    print("\n########################### test_verify_pvc_pod_status ###########################")
    try:
        # print("Sleeping for 10 seconds...")
        sleep(10)
        # print("Resume")
        print("Waiting for PVC %s to come in Bound state..." % objects['PVC']['name'])
        flag, pvc_obj = manager.check_status(timeout, objects['PVC']['name'], kind='pvc', status='Bound',
                                             namespace=objects['PVC']['namespace'])
        if flag is True:
            assert flag is True, \
                "Persistent Volume %s status check timed out, not in Bound state yet..." % objects['PVC']['name']
        """PVC = manager.hpe_read_pvc_object(objects['PVC'])
        assert PVC.status.phase == 'Bound', 'PVC %s is not in Bound state ' % objects['PVC']"""
        print("\nPVC %s is in Bound state" % objects['PVC']['name'])
        # objects["PVC_Volume_name"] = str(PVC.spec.volume_name)[0:31]
        objects['PVC']['volume_name'] = str(pvc_obj.spec.volume_name)[0:31]

        print("Waiting for Pod %s to come in Running state..." % objects['Pod']['name'])
        flag, pvc_obj = manager.check_status(timeout, objects['Pod']['name'], kind='pod', status='Running',
                                             namespace=objects['Pod']['namespace'])
        if flag is True:
            assert flag is True, \
                "Pod %s status check timed out, not in Running state yet..." % objects['Pod']['name']
        print("Pod %s is in Running state" % objects['Pod']['name'])
    except Exception as e:
        print("Exception while verifying pvc and pod status :: %s" % e)
        raise e


def test_verify_on_3par():
    print("\n########################### test_verify_on_3par ###########################")
    try:
        global HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, HPE3PAR_API_URL
        global hpe3par_cli
        HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD = manager.read_array_prop("YAML/test-publish.yml")
        HPE3PAR_API_URL = "https://" + HPE3PAR_IP + ":8080/api/v1"
        print("HPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                      HPE3PAR_IP,
                                                                                                      HPE3PAR_USERNAME,
                                                                                                      (base64.b64decode(HPE3PAR_PWD)).decode(encoding)))

        hpe3par_cli = manager._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                         HPE3PAR_USERNAME, (base64.b64decode(HPE3PAR_PWD)).decode(encoding))
        hpe3par_volume = hpe3par_cli.getVolume(objects['PVC']['volume_name'])
        hpe3par_cli.logout()
        assert hpe3par_volume is not None, "Volume is not created on 3PAR for pvc %s " % objects['PVC']['name']
        print("\n Volume is created successfully on 3PAR for PVC %s " % objects['PVC']['name'])
    except Exception as e:
        print("Exception while verifying volume creation on 3par :: %s" % e)
        raise e


def test_verify_pod_node_names():
    print("\n########################### test_verify_pod_node_names ###########################")
    try:
        # global HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, HPE3PAR_API_URL
    
        #import pytest;
        #pytest.set_trace()
        """hpe3par_cli = manager._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                      HPE3PAR_USERNAME, (base64.b64decode(HPE3PAR_PWD)).decode(encoding))"""
    
        pod_node_name = manager.hpe_get_pod(objects['Pod']['name'],namespace=objects['Pod']['namespace']).spec.node_name
        dot_index = pod_node_name.find('.')
        if dot_index > 0:
            pod_node_name = pod_node_name[0:dot_index]
        # Update node_name where pod is mounted in map for further use
        objects['Pod']['node_name'] = pod_node_name
    
        hpe3par_vlun = hpe3par_cli.getVLUN(objects['PVC']['volume_name'])
        # print("VLUN on 3PAR :: %s " % hpe3par_vlun)
        # print("WWN on 3PAR :: %s " % vv_wwn)
        lun = hpe3par_vlun['lun']
        vv_wwn = hpe3par_vlun['volumeWWN']
        node_name = hpe3par_vlun['hostname']
    
        print("VLUN on 3PAR :: %s " % lun)
        print("WWN on 3PAR :: %s " % vv_wwn)
        print("Pod %s is mounted on %s " % (objects['Pod']['name'], node_name))
    
        #import pytest;
        #pytest.set_trace()
        objects['Pod']['wwn'] = vv_wwn
    
        # test if node name received from pod and 3par are same
        assert str(pod_node_name) == str(node_name)
    except Exception as e:
        print("Exception while verifying node names where pod is mounted :: %s" % e)
        raise e


def test_verify_by_path():
    print("\n########################### test_verify_by_path ###########################")
    try:
        # verify ls -lrth /dev/disk/by-path at node
        # ls_disk = manager.get_command_output(node_name, "ls -lrth /dev/disk/by-path")
        # print("#### ls -lrth output for %s is \n%s " % (node_name,ls_disk))
        # Get iscisi ips
        iscsi_info = hpe3par_cli.getiSCSIPorts()
        global iscsi_ips
        for entry in iscsi_info:
            if entry['IPAddr'] != '0.0.0.0' and entry['IPAddr'] != '15.213.64.63':
              iscsi_ips.append(entry['IPAddr'])
    
        print("ISCSI IPs are: %s " % iscsi_ips)
        print("Verifying output of ls -lrth /dev/disk/by-path...")
        for ip in iscsi_ips:
            print("== For IP::%s " % ip)
            command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-[0-9]*$))$/ {print $NF}' | awk -F'../' '{print $NF}'"
            print("command is %s " % command)
            partitions = manager.get_command_output(objects['Pod']['node_name'], command)
            print("== Partition(s) received for %s are %s", (ip, partitions))
            assert len(partitions) > int(0), "Partition not found for iscsi-ip %s " % ip
            disk_partitions_by_ip[ip] = partitions
    
            for partition in partitions:
                disk_partition.append(partition)
            # print("Partition name %s" % partitions)
    
        print("Partitions :: \n%s" % disk_partitions_by_ip)
        #import pytest;
        #pytest.set_trace()
    except Exception as e:
        print("Exception while verifying partitions for iscsi ip(s) :: %s" % e)
        raise e


def test_verify_multipath():
    print("\n########################### test_verify_multipath ###########################")
    try:
        node_name = objects['Pod']['node_name']
        vv_wwn = objects['Pod']['wwn']
        print("Fetching DM(s)...")
        # fetch dm from /dev/mapper
        # command = "ls -ltrh /dev/mapper/ | awk -v IGNORECASE=1 '$9~/^[0-9]" + vv_wwn.upper() + "/ {print$NF}' | awk -F'../' '{print$NF}'"
        command = "ls -lrth /dev/disk/by-id/ | awk -v IGNORECASE=1 '$9~/^dm-uuid-mpath-[0-9]" + vv_wwn + \
                  "/' | awk -F '../../' '{print$NF}'"
        print("dev/mapper command to get dm :: %s "%command)
        dm = manager.get_command_output(node_name, command)
        print("DM(s) received :: %s " % dm)
    
        # Fetch user friendly multipath name
        print("Fetching user friendly multipath name")
        command = "ls -lrth /dev/mapper/ | awk '$11~/" + dm[0] + "$/' | awk '{print$9}'"
        mpath_name = manager.get_command_output(node_name, command)
        print("mpath received :: %s " % mpath_name)
    
        print("Verifying multipath -ll output...")
        # Verify multipath -ll output
        command = "sudo multipath -ll | awk -v IGNORECASE=1 '/^" + mpath_name[0] + "\s([0-9]" + vv_wwn + ")*/{x=NR+4}(NR<=x){print}'"
    
        import pytest;
        pytest.set_trace()
        
        
        print("multipath -ll command to :: %s " % command)
        paths = manager.get_command_output(node_name, command)
        print("multipath output ::%s \n\n" % paths)
        index = 0
        multipath_failure_flag = 0
        global disk_partition_temp
        disk_partition_temp = disk_partition
        for path in paths:
            if index < 3:
                index += 1
                continue
            # print(path.split())
            col = path.split()
            print(col)
            print(col[2])
    
            if col[2] in disk_partition_temp:
                print("col[2] :: %s " % col[2])
                disk_partition_temp.remove(col[2])
                if col[4] != 'active' or col[5] != 'ready' or col[6] == 'running':
                    print("col[4]:col[5]:col[6] :: %s:%s:%s " % (col[4], col[5], col[6]))
                    multipath_failure_flag+=1
    
        assert multipath_failure_flag != 0, "multipath check failed for %s iscsi ips" % multipath_failure_flag
    except Exception as e:
        print("Exception while verifying multipath :: %s" % e)
        raise e


def test_verify_partition():
    print("\n########################### test_verify_partition ###########################")
    try:
        #import pytest;
        #pytest.set_trace()
        # print("modified disk_partition = %s" % disk_partition_temp)
        global disk_partition_temp
        assert len(disk_partition_temp) == 0, "partition mismatch"
    except Exception as e:
        print("Exception while verifying partitions :: %s" % e)
        raise e


def test_verify_lsscsi():
    print("\n########################### test_verify_lsscsi ###########################")
    try:
        node_name = objects['Pod']['node_name']
        # Verify lsscsi output
        command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
        print("lsscsi command :: %s " % command)
        partitions = manager.get_command_output(node_name, command)
    
        #print("partitions after lsscsi %s " % partitions)
        assert partitions.sort() == disk_partition.sort(), "lsscsi verificatio failed"
        #import pytest;
        #pytest.set_trace()
    except Exception as e:
        print("Exception while verifying lsscsi :: %s" % e)
        raise e


def test_delete_pod():
    print("\n########################### test_delete_pod ###########################")
    try:
        name = objects["Pod"]['name']
        namespace = objects["Pod"]['namespace']
        print("Deleting pod %s..." % name)
        manager.hpe_delete_pod_object_by_name(name, namespace=namespace)

        assert manager.check_if_deleted(timeout, name, "Pod",
                                        namespace=namespace) is True, "Pod %s is not deleted yet " % name
        print("Pod %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting pod :: %s" % e)
        raise e


def test_delete_pvc():
    print("\n########################### test_delete_pvc ###########################")
    try:
        name = objects["PVC"]['name']
        namespace = objects["PVC"]['namespace']
        print("Deleting PVC %s..." % name)
        manager.hpe_delete_pvc_object_by_name(name, namespace=namespace)

        assert manager.check_if_deleted(timeout, name, "PVC", namespace=namespace) is True, "PVC %s is not deleted yet " % name
        print("PVC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting base pvc :: %s" % e)
        raise e


def test_delete_sc():
    print("\n########################### test_delete_sc ###########################")
    try:
        name = objects["SC"]
        print("Deleting SC %s..." % name)
        manager.hpe_delete_sc_object_by_name(name)

        assert manager.check_if_deleted(timeout, name, "SC") is True, "SC %s is not deleted yet " % name
        print("SC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting storage class :: %s" % e)
        raise e


def test_delete_secret():
    print("\n########################### test_delete_secret ###########################")
    try:
        name = objects["Secret"]['name']
        namespace = objects["Secret"]['namespace']
        print("Deleting Secret %s..." % name)
        manager.hpe_delete_secret_object_by_name(name, namespace=namespace)

        assert manager.check_if_deleted(timeout, name, "Secret", namespace=namespace) is True, \
            "Secret %s is not deleted yet " % name
        print("Secret %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting secret :: %s" % e)
        raise e


def test_verify_delete_on_3par():
    try:
        # Check again if PVC is deleted before verifying at 3PAR
        global hpe3par_cli
        pvc_name = objects['PVC']['name']
        pvc_namespace = objects['PVC']['namespace']

        if manager.check_if_deleted(5, pvc_name, "PVC") is False:
            manager.hpe_delete_pvc_object_by_name(pvc_name, namespace=pvc_namespace)

        assert manager.check_if_deleted(timeout, pvc_name, "PVC") is True, \
            "PVC %s is not deleted yet on cluster, not verifying on array " % pvc_name
        print("PVC %s is deleted." % pvc_name)
        hpe3par_volume = hpe3par_cli.getVolume(objects['PVC']['volume_name'])
        hpe3par_cli.logout()
        assert hpe3par_volume is None, "Volume is not deleted from 3PAR after deleting of pvc %s " \
                                       % objects['PVC']['name']
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e


def test_verify_deleted_lun():
    print("\n########################### test_verify_deleted_lun ###########################")
    #import pytest;
    #pytest.set_trace()
    try:
        print("Verifying 'ls -lrth /dev/disk/by-path' entries are cleaned...")
        # verify ls -lrth /dev/disk/by-path at node
        for ip in iscsi_ips:
            print("For IP::%s " % ip)
            command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-0))$/ {print $NF}' | awk -F'../' '{print $NF}'"
            # print("command is %s " % command)
            partitions = manager.get_command_output(objects['Pod']['node_name'], command)
            assert len(partitions) == int(0), "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip
            disk_partitions_by_ip[ip] = partitions

            for partition in partitions:
                disk_partition.append(partition)
            print("Partition name %s" % partitions)

        #import pytest;
        #pytest.set_trace()

        print("Verifying 'multipath -ll' entries are cleaned...")
        #import pytest;
        #pytest.set_trace()
        # Verify multipath -ll output
        command = "multipath -ll | awk -v IGNORECASE=1 '/^([0-9]" + objects['Pod']['wwn'] + \
                  ").*(3PARdata,VV)/{x=NR+4}(NR<=x){print}'"
        # print("multipath -ll command to :: %s " % command)
        paths = manager.get_command_output(objects['Pod']['node_name'], command)
        assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

        #import pytest;
        #pytest.set_trace()

        print("Verifying 'lsscsi' entries are cleaned...")
        #import pytest;
        #pytest.set_trace()
        # Verify lsscsi output
        command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
        partitions = manager.get_command_output(objects['Pod']['node_name'], command)
        print("partitions after lsscsi %s " % partitions)
        assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"

    except Exception as e:
        print("Exception :: %s" % e)
        raise e


