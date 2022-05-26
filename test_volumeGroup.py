import hpe_3par_kubernetes_manager as manager
import time
import yaml
import pytest
import random

import globals 
import logging


timeout = globals.status_check_timeout
pvc_list = []

pod_list = []

# C547899: associate the created volume to volumegroup
def test_volume_group_test_1_sanity():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break
        logging.getLogger().info("Creating volume group class and volume group")

        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "create" in resp, "volume group not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)
        
        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        # Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]
        
        logging.getLogger().info("Adding pvc {0} to volume group {1} ".format(pvc.metadata.name, vol_grp_name))
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        # Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc not added to volume group"
        logging.getLogger().info("pvc {0} added to volume group {1} ".format(pvc.metadata.name, vol_grp_name))
        time.sleep(10)

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name
        time.sleep(20)

        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export'] 
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True

        assert isFilePresent is True, "File not present in base volume"
        logging.getLogger().info("File is present in base volume")

    except Exception as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)


#C547902 Delete volumegroup without removing pvc/volume
def test_volume_group_test_5():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group and volume group class")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True, "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        #Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        
        # Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name, vol_grp_name))
        time.sleep(10)

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"

        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name

        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "deleted" in resp, "volume group not deleted"
        isDeleted = volume_group_delete_status(volGrp_uid)
        assert isDeleted is True, "Volume group not deleted on array"

        command = 'kubectl delete -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "deleted" in resp, "volume group class not deleted"
        
    except Exception as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        

#C547901 Delete a pvc/volume and dis-associate it from volumegroup by deleting pvc/volume
def test_volume_group_test_2():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True, "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc 
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
        namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        logging.getLogger().info("Adding pvc to volume group.")
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        
        #Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name, vol_grp_name))
        time.sleep(10)
        
        # Export volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        time.sleep(20)

        # Checking volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"
        logging.getLogger().info("File present on volume")


        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name
       
        manager.delete_pvc(base_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, base_pvc_obj.metadata.name, "Pod", namespace=base_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % base_pvc_obj.metadata.name

        # Checking in array if pvc is deleted from volume group
        Del_flag = pvc_delete_status(volGrp_uid,volume_name )
        assert Del_flag is True, "Pvc not deleted from volume group"
        logging.getLogger().info("Pvc {0} deleted from volume group".format(volume_name))

        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "deleted" in resp, "Volume group not deleted"
        isDeleted = volume_group_delete_status(volGrp_uid)
        assert isDeleted is True, "Volume group not deleted on array"
        logging.getLogger().info("Volume group deleted from array")

        command = 'kubectl delete -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        time.sleep(10)


    except Exception as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)


#C547905 Add already existing pvc not part of any vg or vvset to vg
def test_volume_group_test_6():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    yml_pvc = '%s/volume_group/pvc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    pod_vg = '%s/volume_group/pod_vg.yaml' % globals.yaml_dir
    ymlpod = '%s/volume_group/ymlpod.yaml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    global pvc_list
    global pod_list
    isFilePresent = False

    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group and volume group class")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]


        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on the array".format(volGrp_uid))

        #Creating sc and pvc 
        sc = manager.create_sc(yml)
        count =0
        with open(yml_pvc, "r") as ymlpvc:
            el_pvc = list(yaml.safe_load_all(ymlpvc))
            while True:
                if count < 3:
                    el_pvc[0]['metadata']['name'] = pvc_random_name()
                    pvc = manager.hpe_create_pvc_object(el_pvc[0])
                    count = count +1
                    logging.getLogger().info("Check in events if volume is created...")
                    flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
        namespace=pvc.metadata.namespace)

                    assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

                    yaml_values = manager.get_details_for_volume(volGrp)
                    vol_grp_name = yaml_values['name']
                    volume_name = base_pvc_obj.spec.volume_name[:31]

                    body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
                    patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

                    #Checking in array if pvc is added to volume group
                    is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
                    assert is_pvc_added is True, "Pvc {0} not added to volume group".format(pvc.metadata.name)
                    logging.getLogger().info("Pvc {0} added to volume group {1} ".format(volume_name, volGrp_uid))
                    #pvc_list += [base_pvc_obj.spec.volume_name[:31]]
                    pvc_list += [el_pvc[0]['metadata']['name']]
                    time.sleep(10)
                else:
                    break

        # Export base volume
        i =0
        while True:
            if i > 2:
                break
            else:
                with open(ymlpod, 'w') as outfile, open(pod_vg, 'r') as infile:
                    for line in infile:
                        if line.startswith("  name:"):
                            line = "  name: " + pod_random_name() + "\n"
                        if line.startswith("        claimName:"):
                            line = "        claimName: " + pvc_list[i]

                        outfile.write(line)

                pod = manager.create_pod(ymlpod)
                flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
                assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

                time.sleep(20)

                # Checking base volume data
                command = ['/bin/sh', '-c', 'ls -l /export']
                data = manager.hpe_connect_pod_container(pod.metadata.name, command)
                if any("mynewdata.txt" in x for x in data.split('\n')):
                    isFilePresent = True
                    assert isFilePresent is True, "File not present in base volume"
                    logging.getLogger().info("File present on base volume")
                    pod_list  += [base_pod_obj.metadata.name]
                i =i+1

        # Deleting created resources
        for pod in pod_list:
            manager.hpe_delete_pod_object_by_name(pod, globals.namespace)
            flag = manager.check_if_deleted(180, pod, "Pod", namespace=globals.namespace)
            assert flag is True, "POD %s delete status check timedout..." % pod

        for pvc in pvc_list:
            manager.delete_pvc(pvc)
            flag = manager.check_if_deleted(2, pvc, "PVC", namespace=globals.namespace)
            assert flag is True, "PVC %s delete status check timedout..." % pvc

        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        time.sleep(10)
    
        command = 'kubectl delete -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        time.sleep(10)

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup_mul(sc, pvc, pod)


#C547907 Add/edit a volume that is already part of another vg
def test_volume_group_test_10():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    volGrp_new = '%s/volume_group/volume-group_1.yaml' % globals.yaml_dir
    volGrpClass_new = '%s/volume_group/volume-group-class_1.yml' % globals.yaml_dir 
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Pvc creating volume group and volume group class")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        #Creating pvc and sc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        
        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        #Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc {0} not added to volume group".format(pvc.metadata.name)
        logging.getLogger().info("Pvc {0} added to volume group {1} ".format(volume_name, volGrp_uid))
        time.sleep(10)

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        time.sleep(20)

        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"
        logging.getLogger().info("File present on base volume")


        #Creating the new volume set
        with open(volGrp_new, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name_new = el['metadata']['name']
                    break
        logging.getLogger().info("Creating second volume set")

        command = 'kubectl create -f ' + volGrpClass_new
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp_new
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name_new + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id_new = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid_new = id_new[0].split()[1][:27]

        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid_new)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Second volume group {0} created on array ".format(volGrp_uid_new))

        yaml_values_new = manager.get_details_for_volume(volGrp_new)
        vol_grp_name_new = yaml_values_new['name']
        new_volume_name = base_pvc_obj.spec.volume_name[:31]

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name_new} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        #Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid_new, new_volume_name)
        assert is_pvc_added is True, "Pvc {0} not added to volume group".format(pvc.metadata.name)
        logging.getLogger().info("Pvc {0} added to volume group {1} ".format(new_volume_name, volGrp_uid_new))

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e
    
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)
        cleanup_volume_group(volGrp_new, volGrpClass_new, volGrp_uid_new)


#C549392 clone volume which is part of volumegroup
def test_volume_group_test_13():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = True
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break
        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        
        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        #Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc {0} not added to volume group".format(pvc.metadata.name)
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name,volGrp_uid))
        time.sleep(10)

        # Checking base volume details on array
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        time.sleep(20)

        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"

        # Creating clone of pvc in vvset
        yml_clone = '%s/volume_group/sc_clone.yaml' % globals.yaml_dir
        sc_clone = manager.create_sc(yml_clone)
        pvc_clone = manager.create_pvc(yml_clone)
        logging.getLogger().info("Check in events if clone volume is created...")
        flag, base_pvc_clone_obj = manager.check_status(30, pvc_clone.metadata.name, kind='pvc', status='Bound',
                                                  namespace=pvc_clone.metadata.namespace)
        clone_volume = base_pvc_clone_obj.spec.volume_name[:31]
        assert flag is True, "Clone PVC %s status check timed out, not in Bound state yet..." % base_pvc_clone_obj.metadata.name

        # Checking in array if clone pvc is not part of volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert clone_volume not in volume_set['setmembers'], "Pvc not added to volume group"

        # Checking clone volume details on array
        clone_volume_details = manager.get_volume_from_array(globals.hpe3par_cli, clone_volume)

        # Export clone volume
        pod_clone = manager.create_pod(yml_clone)
        flag, base_pod_clone_obj = manager.check_status(timeout, pod_clone.metadata.name, kind='pod', status='Running',
                                                  namespace=pod_clone.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod_clone.metadata.name

        time.sleep(20)

        # Checking base volume data in cloned volume and new write to the cloned volume
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod_clone.metadata.name, command)
        isFilePresent = False
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in clone volume"

        isFilePresent = False
        if any("myclonedata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in clone volume"

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e
    
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        cleanup(sc_clone, pvc_clone, pod_clone)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)


# C549381 expand volume which is part of volumegroup
def test_volume_group_test_14():
    yml = '%s/volume_group/sc_expand.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' + globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        # Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True, "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                  namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = {'metadata': {'annotations': {'csi.hpe.com/volume-group': vol_grp_name}}}
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name, globals.namespace, body)

        # Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc {0} not added to volume group".format(pvc.metadata.name)
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name, volGrp_uid))
        time.sleep(10)

        # expanding volume size of the array
        cap_vol = '30'
        body = {'spec': {'resources': {'requests': {'storage': cap_vol + 'Gi'}}}}
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name, globals.namespace, body)
        time.sleep(30)

        voldata = manager.get_volume_from_array(globals.hpe3par_cli, base_pvc_obj.spec.volume_name[:31])
        assert voldata['sizeMiB'] == int(cap_vol) * 1024, "Volume expand failed"

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                                  namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        time.sleep(20)
        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)


# C547909 Add volume part of different domain to vg
def test_volume_group_test_15():
    yml = '%s/volume_group/sc_expand.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class-domain.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isFilePresent = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' + globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        # Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True, "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                  namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = {'metadata': {'annotations': {'csi.hpe.com/volume-group': vol_grp_name}}}
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name, globals.namespace, body)

        # Checking if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is False, "Pvc added to volume group"
        logging.getLogger().info("pvc {0} not added to volume group {1} ".format(pvc.metadata.name, vol_grp_name))

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)


# C547900 Disassociate a pvc/volume from volumegroup by pvc edit
def test_volume_group_test_16():
    yml = '%s/volume_group/sc_expand.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break

        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' + globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        # Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True, "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                  namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        body = {'metadata': {'annotations': {'csi.hpe.com/volume-group': vol_grp_name}}}
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name, globals.namespace, body)


        # Checking in array if pvc is added to volume group
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name, volGrp_uid))
        time.sleep(10)

        # disassociating pvc from volume group
        body = {'metadata': {'annotations': {'csi.hpe.com/volume-group': ""}}}
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name, globals.namespace, body)

        Del_flag = pvc_delete_status(volGrp_uid, volume_name)
        assert Del_flag is True, "Pvc not deleted from volume group"
        logging.getLogger().info("Pvc {0} removed from volume group {1}".format(pvc.metadata.name, volGrp_uid))
        time.sleep(10)

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)


def test_volume_group_test_hostSeesVLUN():
    yml = '%s/volume_group/sc_vg_hostSeesVLUN.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None

    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                break

        with open(yml, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "StorageClass":
                    if 'hostSeesVLUN' in el['parameters']:
                        hostSeesVLUN = el['parameters']['hostSeesVLUN']

                break
        logging.getLogger().info("Creating volume group class and volume group")

        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group class not created"

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "created" in resp, "volume group not created"

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        # Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        # Checking in array if volume group is created
        isPresent = volume_group_create_status(volGrp_uid)
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Volume group {0} created on array".format(volGrp_uid))

        # Creating sc and pvc
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc.metadata.name

        yaml_values = manager.get_details_for_volume(volGrp)
        vol_grp_name = yaml_values['name']
        volume_name = base_pvc_obj.spec.volume_name[:31]

        logging.getLogger().info("Adding pvc {0} to volume group {1} ".format(pvc.metadata.name, vol_grp_name))
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        # Checking if volume group has members list
        is_pvc_added = pvc_add_status(volGrp_uid, volume_name)
        assert is_pvc_added is True, "Pvc not added to volume group"
        logging.getLogger().info("pvc {0} added to volume group {1} ".format(pvc.metadata.name, vol_grp_name))
        time.sleep(10)

        # Export base volume
        pod = manager.create_pod(yml)
        flag, base_pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        # Adding hostSeesVLUN check
        hpe3par_active_vlun = manager.get_all_active_vluns(globals.hpe3par_cli, volume_name)
        for vlun_item in hpe3par_active_vlun:
            if hostSeesVLUN == "true":
                assert vlun_item['type'] == globals.HOST_TYPE, "hostSeesVLUN parameter validation failed for volume %s" % volume_name
            else:
                assert vlun_item['type'] == globals.MATCHED_SET, "hostSeesVLUN parameter validation failed for volume %s" % volume_name
        logging.getLogger().info("Successfully completed hostSeesVLUN parameter check")


        # Checking base volume data
        command = ['/bin/sh', '-c', 'ls -l /export']
        data = manager.hpe_connect_pod_container(pod.metadata.name, command)
        if any("mynewdata.txt" in x for x in data.split('\n')):
            isFilePresent = True
        assert isFilePresent is True, "File not present in base volume"
        logging.getLogger().info("File is present in base volume")

    except Exception as e:
        logging.getLogger().error("Exception in volume group testcase :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)
        cleanup_volume_group(volGrp, volGrpClass, volGrp_uid)



def volume_group_create_status(volGrp_uid):
    # Checking in array if volume group is created
    t = 0
    isPresent = False
    while True:
        volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
        for m in volume_sets['members']:
            if m['name'] == volGrp_uid:
                isPresent = True
                break
        if isPresent:
            break
        else:
            t = t + 5
            time.sleep(5)
        if int(t) > int(timeout):
            break
    return isPresent

def volume_group_delete_status(volGrp_uid):
    # Deleting volume group
    t = 0
    isPresent = True
    while True:
        volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
        for m in volume_sets['members']:
            if m['uuid'] == volGrp_uid:
                isPresent = False
                break
        if not isPresent:
            t = t + 5
            time.sleep(5)
        else:
            break
        if int(t) > int(timeout):
            break
    return isPresent


def pvc_add_status(volGrp_uid, volume_name):
    # Checking if volume group has member list.
    count = 0
    isSet = False
    while True:
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        if 'setmembers' in volume_set.keys() and volume_name in volume_set['setmembers']:
            isSet = True
            break
        else:
            count = count + 10
            time.sleep(10)
        if int(count) > int(timeout):
            break
    return isSet

def pvc_delete_status(volGrp_uid, volume_name):
    # Checking in array if pvc is deleted from volume group
    count = 0
    Del_flag = False
    while True:
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        if 'setmembers' not in volume_set.keys() or volume_name not in volume_set['setmembers']:
            Del_flag = True
            break
        else:
            count = count + 10
            time.sleep(10)
        if int(count) > int(timeout):
            break
    return Del_flag


def pvc_random_name():
    return u'pvc-{0:x}'.format(random.getrandbits(32))

def pod_random_name():
    return u'pod-{0:x}'.format(random.getrandbits(32))




def cleanup(sc, pvc, pod, **kwargs):
    try:
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

    except Exception as e:
        logging.getLogger().error("Exception  :: %s" % e)
        raise e
    
    print("====== cleanup :END =========")


def cleanup_volume_group( volGrp, volGrpClass, volGrp_uid=None ):
    try:
        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        assert "deleted" in resp, "volume group not deleted"
        if not volGrp_uid:
            isDeleted = volume_group_delete_status(volGrp_uid)
            assert isDeleted is True, "Volume group not deleted on array"

        command = 'kubectl delete -f ' + volGrpClass
        resp = manager.get_command_output_string(command)
        assert "deleted" in resp, "volume group class not deleted"

    except Exception as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e

def cleanup_mul(sc, pvc, pod):
    print("====== cleanup :START =========")
    global pvc_list
    global pod_list
    #logging.info("====== cleanup after failure:START =========")
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    if not pod_list:
        for pod in pod_list:
            if manager.check_if_deleted(2, pod, "Pod", namespace=globals.namespace) is False:
                manager.hpe_delete_pod_object_by_name(pod, globals.namespace)
                flag = manager.check_if_deleted(180, pod, "Pod", namespace=globals.namespace)
                assert flag is True, "POD %s delete status check timedout..." % pod

    if not pvc_list:
        for pvc in pvc_list:
            if manager.check_if_deleted(2, pvc, "PVC", namespace=globals.namespace) is False:
                manager.delete_pvc(pvc)
                flag = manager.check_if_deleted(2, pvc, "PVC", namespace=globals.namespace)
                assert flag is True, "PVC %s delete status check timedout..." % pvc


    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", None) is False:
        manager.delete_sc(sc.metadata.name)

    command = 'kubectl delete -f ' + volGrp
    resp = manager.get_command_output_string(command)

    command = 'kubectl delete -f ' + volGrpClass
    resp = manager.get_command_output_string(command)


    print("====== cleanup :END =========")



