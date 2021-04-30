import hpe_3par_kubernetes_manager as manager
import time
import yaml
import pytest
import random

import globals 
import logging


timeout = 900
pvc_list = []

pod_list = []

# C547899: associate the created volume to volumegroup
def test_volume_group_test_1():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isPresent = False
    isValid = False
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

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)
        
        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]
        

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1 
                break
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
        
        logging.getLogger().info("Adding pvc {0} to volume group {1} ".format(pvc.metadata.name, vol_grp_name))
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(20)

        #Checking in array if pvc is added to volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
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
            isPresent = True
        assert isPresent is True, "File not present in base volume"
        logging.getLogger().info("File is present in base volume")
            


        # Deleting created resources
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
        cleanup(sc, pvc, pod)


#C547902 Delete volumegroup without removing pvc/volume
def test_volume_group_test_5():
    yml = '%s/volume_group/sc_vg.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isPresent = False
    isValid = False
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

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
        assert isPresent is True , "Volume group not created on array"
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

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(20)

        #Checking in array if pvc is added to volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name, vol_grp_name))
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
            isPresent = True
        assert isPresent is True, "File not present in base volume"

        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name

        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        time.sleep(30)

        isPresent = True

        #Deleting volume group
        volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
        for m in volume_sets['members']:
            if m['uuid'] ==  id[0].split()[1]:
                isPresent = False
        assert isPresent is True , "Volume group is not deleted"
        logging.getLogger().info("Volume group {1} deleted from array".format(pvc.metadata.name, vol_grp_name))


        manager.delete_pvc(base_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, base_pvc_obj.metadata.name, "PVC", namespace=base_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % base_pvc_obj.metadata.name

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name
        #manager.delete_secret(secret.metadata.name, secret.metadata.namespace)


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
    isPresent = False
    isValid = False
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

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
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

        logging.getLogger().info("Adding pvc to volume group.")
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(30)

        #Checking in array if pvc is added to volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
        time.sleep(10)
        logging.getLogger().info(" Pvc {0} added to volume group {1} created on array".format(pvc.metadata.name,vol_grp_name))

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
            isPresent = True
        assert isPresent is True, "File not present in base volume"
        logging.getLogger().info("File present on volume")


        # Deleting created resources
        manager.hpe_delete_pod_object_by_name(base_pod_obj.metadata.name, base_pod_obj.metadata.namespace)
        flag = manager.check_if_deleted(180, base_pod_obj.metadata.name, "Pod", namespace=base_pod_obj.metadata.namespace)
        assert flag is True, "POD %s delete status check timedout..." % base_pod_obj.metadata.name
       
        manager.delete_pvc(base_pvc_obj.metadata.name)
        flag = manager.check_if_deleted(2, base_pvc_obj.metadata.name, "Pod", namespace=base_pvc_obj.metadata.namespace)
        assert flag is True, "PVC %s delete status check timedout..." % base_pvc_obj.metadata.name

        #Checking in array if pvc is deleted from volume group
        count = 0
        while True:

            volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
            time.sleep(10)
            #if base_pvc_obj.spec.volume_name[:31] not in volume_set['setmembers']:
            if 'setmembers' not in volume_set.keys():
                Del_flag = True
                break
            if int(count)>int(timeout):
                break
            count = count +1
            
        assert Del_flag is True, "Pvc not deleted from volume group"
        logging.getLogger().info("Pvc {0} deleted from volume group".format(base_pvc_obj.spec.volume_name[:31]))

        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)
        time.sleep(10)

        #Checking if volume group is removed from array
        volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
        for m in volume_sets['members']:
            if m['uuid'] ==  id[0].split()[1]:
                isPresent = False
        assert isPresent is True , "Volume group is not deleted"
        logging.getLogger().info("Volume group deleted from array")
        #assert base_pvc_obj.spec.volume_name[:31] not in volume_set['setmembers'], "Pvc not added to volume group"

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name
        #manager.delete_secret(secret.metadata.name, secret.metadata.namespace)


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

    isPresent = False
    isValid = False
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

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]


        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
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

                    body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
                    patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
                    time.sleep(30)

                    #Checking in array if pvc is added to volume group
                    volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
                    assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
                    logging.getLogger().info("Pvc {0} added to volume group {1} ".format(base_pvc_obj.spec.volume_name[:31], volGrp_uid))
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
                    isPresent = True
                    assert isPresent is True, "File not present in base volume"
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

        '''#Checking in array if pvc is added to volume group
        volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
        #assert base_pvc_obj.spec.volume_name[:31] not in volume_set['setmembers'], "Pvc not added to volume group"'''

        manager.delete_sc(sc.metadata.name)
        flag = manager.check_if_deleted(2,  sc.metadata.name, "SC", None)
        assert flag is True, "SC %s delete status check timedout..." % sc.metadata.name
        #manager.delete_secret(secret.metadata.name, secret.metadata.namespace)


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
    isPresent = False
    isValid = False
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

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
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

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(30)

        #Checking in array if pvc is added to volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1} ".format(base_pvc_obj.spec.volume_name[:31], volGrp_uid))
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
            isPresent = True
        assert isPresent is True, "File not present in base volume"
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

        command = 'kubectl create -f ' + volGrp_new
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name_new + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id_new = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid_new = id_new[0].split()[1][:27]

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets_new = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets_new['members']:
                if m['name'] ==  id_new[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
        assert isPresent is True , "Volume group not created on array"
        logging.getLogger().info("Second volume group {0} created on array ".format(volGrp_uid_new))

        yaml_values_new = manager.get_details_for_volume(volGrp_new)
        vol_grp_name_new = yaml_values_new['name']

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name_new} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)

        #Checking in array if pvc is added to volume group
        count =0

        while True:

            volume_set_new = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid_new)
            time.sleep(10)
            #if base_pvc_obj.spec.volume_name[:31] not in volume_set['setmembers']:
            if 'setmembers' in volume_set_new.keys():
                Del_flag = True
                break
            if int(count)>int(timeout):
                break
            count = count +1

        assert base_pvc_obj.spec.volume_name[:31] in volume_set_new['setmembers'], "Pvc not added to volume group"
        time.sleep(10)
        logging.getLogger().info("Pvc {0} added to volume group {1} ".format(base_pvc_obj.spec.volume_name[:31], volGrp_uid_new))

 

        

        # Deleting created resources
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
        cleanup(sc, pvc, pod)


'''#C549381 expand volume which is part of volumegroup
def test_volume_group_test_13():
    yml = '%s/volume_group/sc_expand.yaml' % globals.yaml_dir
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    sc = None
    pvc = None
    pod = None
    isPresent = False
    isValid = False
    try:
        with open(volGrp, "r") as ymlfile:
            elements = list(yaml.safe_load_all(ymlfile))
            for el in elements:
                if str(el.get('kind')) == "VolumeGroup":
                    volGrp_name = el['metadata']['name']
                    break
        import pdb
        pdb.set_trace()
        logging.getLogger().info("Creating volume group class and volume group")
        command = 'kubectl create -f ' + volGrpClass
        resp = manager.get_command_output_string(command)

        command = 'kubectl create -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl describe volumegroup ' + volGrp_name + ' -n ' +globals.namespace
        resp = manager.get_command_output_string(command)

        #Getting volumegroup uid
        id = [s for s in resp.split('\n') if "UID" in s]
        volGrp_uid = id[0].split()[1][:27]

        #Checking in array if volume group is created
        t = 0
        while True:
            isPresent = False
            volume_sets = manager.get_volume_sets_from_array(globals.hpe3par_cli)
            for m in volume_sets['members']:
                if m['name'] ==  id[0].split()[1][:27]:
                    isPresent = True
                    break
            if  isPresent == True:
                break
            if int(t) > int(timeout):
                t = t +1
                break
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

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/volume-group' : vol_grp_name} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(30)



        #Checking in array if pvc is added to volume group
        volume_set = manager.get_volume_set_from_array(globals.hpe3par_cli, volGrp_uid)
        assert base_pvc_obj.spec.volume_name[:31] in volume_set['setmembers'], "Pvc not added to volume group"
        logging.getLogger().info("Pvc {0} added to volume group {1}".format(pvc.metadata.name,volGrp_uid))
        time.sleep(10)

        cap_vol = '30Gi'
        body = { 'status': { 'capacity': { 'storage' : cap_vol} } }
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(30)

        voldata = manager.get_volume_from_array(globals.hpe3par_cli, base_pvc_obj.spec.volume_name[:31])
        assert voldata['sizeMiB'] == cap_vol, "Volume expand failed"


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
            isPresent = True
        assert isPresent is True, "File not present in base volume"



        # Deleting created resources
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
        cleanup(sc, pvc, pod)'''




def pvc_random_name():
    return u'pvc-{0:x}'.format(random.getrandbits(32))

def pod_random_name():
    return u'pod-{0:x}'.format(random.getrandbits(32))




def cleanup(sc, pvc, pod):
    print("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    volGrp = '%s/volume_group/volume-group.yaml' % globals.yaml_dir
    volGrpClass = '%s/volume_group/volume-group-class.yml' % globals.yaml_dir
    volGrp_new = '%s/volume_group/volume-group_1.yaml' % globals.yaml_dir
    volGrpClass_new = '%s/volume_group/volume-group-class_1.yml' % globals.yaml_dir

    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", None) is False:
        manager.delete_sc(sc.metadata.name)
    try:
        command = 'kubectl delete -f ' + volGrp
        resp = manager.get_command_output_string(command)

        command = 'kubectl delete -f ' + volGrpClass
        resp = manager.get_command_output_string(command)

        command = 'kubectl delete -f ' + volGrp_new
        resp = manager.get_command_output_string(command)

        command = 'kubectl delete -f ' + volGrpClass_new
        resp = manager.get_command_output_string(command)
    except Exception:
        pass
    
    print("====== cleanup :END =========")


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

    #logging.info("====== cleanup after failure:END =========")

