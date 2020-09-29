import pytest
import yaml
from kubernetes import client, config
from time import sleep
from hpe3parclient.client import HPE3ParClient
import paramiko
import os
import json
from hpe3parclient.exceptions import HTTPNotFound
import base64
import datetime
import logging

config.load_kube_config()
k8s_storage_v1 = client.StorageV1Api()
k8s_core_v1 = client.CoreV1Api()
k8s_extn_apps_v1 = client.ExtensionsV1beta1Api()
k8s_api_extn_v1 = client.ApiextensionsV1beta1Api()
k8s_rbac_auth_v1 = client.RbacAuthorizationV1Api()
k8s_apps_v1 = client.AppsV1Api()

timeout = 180


def hpe_create_sc_object(yml):
    try:
        resp = k8s_storage_v1.create_storage_class(body=yml)
        # print("Storage Class created. status=%s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        #logging.error("Exception :: %s" % e)
        raise e


def hpe_create_secret_object(yml):
    try:
        namespace = "default"
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        resp = obj = k8s_core_v1.create_namespaced_secret(namespace=namespace, body=yml)
        # print("Secret %s created" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        print("Exception while creating secret:: %s" % e)
        #logging.error("Exception while creating secret:: %s" % e)
        raise e


def hpe_create_pvc_object(yml):
    try:
        namespace = "default"
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        pvc = k8s_core_v1.create_namespaced_persistent_volume_claim(namespace=namespace, body=yml)
        # print("PVC created. status=%s" % pvc.status.phase)
        return pvc
    except client.rest.ApiException as e:
         print("Exception :: %s" % e)
         raise e


def hpe_create_pod_object(yml):
    try:
         namespace = "default"
         if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
         pod = k8s_core_v1.create_namespaced_pod(namespace=namespace, body=yml)
         return pod
    except client.rest.ApiException as e:
          print("Exception :: %s" % e)
          raise e


def hpe_read_pvc_object(pvc_name, namespace="default"):
    try:
        pvc = k8s_core_v1.read_namespaced_persistent_volume_claim(pvc_name, namespace=namespace)
        return pvc
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_delete_pvc_object_by_name(pvc_name, namespace="default"):
    try:
        pvc = k8s_core_v1.delete_namespaced_persistent_volume_claim(pvc_name, namespace=namespace)
    except client.rest.ApiException as e:
        print("Exception while deleting pvc:: %s" % e)
        raise e


def hpe_delete_secret_object_by_name(secret_name, namespace="default"):
    try:
        pvc = k8s_core_v1.delete_namespaced_secret(secret_name, namespace=namespace)
    except client.rest.ApiException as e:
        print("Exception while deleting secret:: %s" % e)
        raise e


def hpe_delete_sc_object_by_name(sc_name):
    try:
        pvc = k8s_storage_v1.delete_storage_class(sc_name)
    except client.rest.ApiException as e:
        print("Exception while deleting sc:: %s" % e)
        raise e

def hpe_delete_pod_object_by_name(pod_name, namespace = "default"):
    try:
        pvc = k8s_core_v1.delete_namespaced_pod(pod_name, namespace=namespace)
    except client.rest.ApiException as e:
        print("Exception while deleting sc:: %s" % e)
        raise e


def hpe_list_pvc_objects(namespace="Default"):
    try:
        pvc_list = k8s_core_v1.list_namespaced_persistent_volume_claim(namespace=namespace)
        return pvc_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e

def hpe_list_pvc_objects_names(namespace="Default"):
    try:
        pvc_names = []
        pvc_list = hpe_list_pvc_objects(namespace)
        for pvc in pvc_list.items:
            pvc_names.append(pvc.metadata.name)

        return pvc_names
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_sc_objects():
    try:
        sc_list = k8s_storage_v1.list_storage_class()
        return sc_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_sc_objects_names():
    try:
        sc_names = []
        sc_list = hpe_list_sc_objects()
        for sc in sc_list.items:
            sc_names.append(sc.metadata.name)
        return sc_names
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_secret_objects(namespace="Default"):
    try:
        secret_list = k8s_core_v1.list_namespaced_secret(namespace=namespace)
        return secret_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_secret_objects_names(namespace="Default"):
    try:
        secret_names = []
        secret_list = hpe_list_secret_objects(namespace=namespace)
        for secret in secret_list.items:
            secret_names.append(secret.metadata.name)

        return secret_names
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_pod_objects(namespace="Default", **kwargs):
    try:
        # print("kwargs :: keys :: %s,\n values :: %s" % (kwargs.keys(), kwargs.values()))
        # print("value :: %s " % kwargs['label'])
        # pod_list = k8s_core_v1.list_namespaced_pod(namespace=namespace, label_selector=kwargs['label'])
        pod_list = k8s_core_v1.list_namespaced_pod(namespace=namespace)
        return pod_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_pod_objects_names(namespace="Default"):
    try:
        pod_names = []
        pod_list = hpe_list_pod_objects(namespace=namespace)
        for pod in pod_list.items:
            pod_names.append(pod.metadata.name)

        return pod_names
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_list_node_objects():
    try:
        node_list = k8s_core_v1.list_node()
        return node_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e



def check_if_deleted(timeout, name, kind, namespace="Default"):
    time = 0
    flag = True

    # print("timeout :: %s" % timeout)
    # print("name :: %s" % name)
    # print("kind :: %s" % kind)

    while True:
        if kind == 'PVC':
            obj_list = hpe_list_pvc_objects_names(namespace=namespace)
        elif kind == 'SC':
            obj_list = hpe_list_sc_objects_names()
        elif kind == 'Secret':
            obj_list = hpe_list_secret_objects_names(namespace=namespace)
        elif kind == 'Pod':
            obj_list = hpe_list_pod_objects_names(namespace=namespace)
        elif kind == 'Crd':
            obj_list = hpe_list_crds()
        else:
            print("Not a supported kind")
            flag = False
            break
        # print(obj_list)
        print(".", end='', flush=True)
        if name not in obj_list:
            break

        if int(time) > int(timeout):
            print("\n%s not yet deleted. Taking longer than expected..." % kind)
            flag = False
            break
        time += 1
        sleep(1)

    return flag


def read_array_prop(yml):
    try:
        HPE3PAR_IP = None
        HPE3PAR_USERNAME = None
        HPE3PAR_PWD = None
        PROTOCOL = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "Secret":
                    HPE3PAR_IP = el['stringData']['backend']
                    HPE3PAR_USERNAME = el['stringData']['username']
                    HPE3PAR_PWD = el['data']['password']
                if str(el.get('kind')) == "StorageClass":
                    PROTOCOL = el['parameters']['accessProtocol']
        print("HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD))
        return HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, PROTOCOL
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e


def _hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD):
    # Login to 3Par array and initialize connection for WSAPI calls
    hpe_3par_cli = HPE3ParClient(HPE3PAR_API_URL, False, False, None, True)
    hpe_3par_cli.login(HPE3PAR_USERNAME, HPE3PAR_PWD)
    hpe_3par_cli.setSSHOptions(HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD)
    return hpe_3par_cli


def check_event(kind, name):
    try:
        event_list = k8s_core_v1.list_event_for_all_namespaces()
        status = None
        message = None
        if kind == 'pvc':
            k8s_kind = 'PersistentVolumeClaim'
            completion_status = ['ProvisioningSucceeded', 'ProvisioningFailed']
        if kind == 'pod':
            k8s_kind = 'Pod'
            completion_status = ['SucceededMount', 'FailedMount', 'FailedScheduling', 'Mount']
        for event in event_list.items:
            if event.involved_object.kind == k8s_kind and event.involved_object.name == name:
                if event.reason in completion_status:
                    status = event.reason
                    message = event.message
                    break
        return status, message
    except Exception as e:
        print("Exception while fetching events for %s,%s :: %s" % (kind, name, e))
        raise e


def check_status(timeout_set, name, kind, status, namespace="default"):
    time = 0
    flag = True
    # print("timeout :: %s" % timeout)
    # print("time :: %s" % time)
    # print("kind :: %s" % kind)
    # print("status :: %s" % status)
    if kind == 'pod':
        timeout_set = 180
    else:
        timeout_set = 180
    print("\nChecking for %s to come in %s state..." % (kind, status))
    while True:
        obj = ""
        if kind == 'pv':
            obj = k8s_core_v1.read_persistent_volume(name)
        elif kind == 'pvc':
            obj = k8s_core_v1.read_namespaced_persistent_volume_claim(name, namespace)
        elif kind == 'pod':
            obj = k8s_core_v1.read_namespaced_pod(name, namespace)
        elif kind == 'deployment':
            obj = k8s_extn_apps_v1.read_namespaced_deployment(name, namespace)
            print(obj)
        else:
            print("\nNot a supported kind")
            flag = False
            break
        # print("obj.status.phase :: %s" % obj.status.phase)
        print(".", end='', flush=True)
        if kind == 'deployment':
            replica_total = 0
            replica_avail = 0

            if obj.status.replicas is not None:
                replica_total = obj.status.replicas

            if obj.status.available_replicas is not None:
                replica_avail = obj.status.available_replicas
            if replica_total == replica_avail:
                break
        else:
            if obj.status.phase == status:
                break

        if int(time) > int(timeout_set):
            print("\n%s not yet in %s state. Taking longer than expected..." % (kind, status))
            # print("obj :: %s" % obj)
            flag = False
            break
        time += 1
        sleep(1)

    if flag is True:
        print("\n%s has come to %s state!!! It took %s seconds" % (kind, status, str(datetime.timedelta(0, time))))
    return flag, obj


def hpe_get_pod(pod_name, namespace = "default"):
    try:
        return k8s_core_v1.read_namespaced_pod(pod_name,namespace=namespace)
    except Exception as e:
        print("Exception :: %s" % e)
        raise e


def get_command_output(node_name, command):
    try:
        # print("Executing command...")
        ssh_client = paramiko.SSHClient()
        # print("ssh client %s " % ssh_client)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # print("host key set")
        # print("node_name = %s, command = %s " % (node_name, command))
        ssh_client.connect(hostname=node_name)
        # ssh_client.connect(node_name, username='vagrant', password='vagrant', key_filename='/home/vagrant/.ssh/id_rsa')
        # ssh_client.connect(node_name, username='vagrant', password='vagrant', look_for_keys=False, allow_agent=False)
        # print("connected...")
        # execute command and get output
        stdin,stdout,stderr=ssh_client.exec_command(command)
        # print("stdout :: %s " % stdout.read())
        command_output = []
        while True:
            line = stdout.readline()
            if not line:
                break
            command_output.append(str(line).strip())
            print(line)
        # command_output = stdout.read()

        # print("stdin :: " % stdin.readlines())
        # print("stderr :: %s" % stderr.read())
        ssh_client.close()

        return command_output
    except Exception as e:
        print("Exception while ssh %s " % e)


def get_command_output_string(command):
    try:
        stream = os.popen(command)
        output = stream.read()
        return output
    except Exception as e:
        print("Exception while executing command %s " % e)
        

def hpe_list_crds():
    try:
        crd_names = []
        crd_list = k8s_api_extn_v1.list_custom_resource_definition()
        for crd in crd_list.items:
            crd_names.append(crd.metadata.name)

        return crd_names
    except Exception as e:
        print("Exception while listing crd(s) %s " % e)

def hpe_create_crd(yml):
    try:
        pod = k8s_api_extn_v1.create_custom_resource_definition(body=yml)
    except Exception as e:
        print("Exception while creating crd %s " % e)


def hpe_delete_crd(name):
    try:
        crd_del_res = k8s_api_extn_v1.delete_custom_resource_definition(name)
    except Exception as e:
        print("Exception while deleting crd %s " % e)


def hpe_read_sa(sa_name, sa_namespace):
    try:
        obj = k8s_core_v1.read_namespaced_service_account(sa_name, sa_namespace)
        return obj
    except Exception as e:
        print("Exception while reading sa %s " % e)


def hpe_create_sa(yml, sa_namespace):
    try:
        k8s_core_v1.create_namespaced_service_account(sa_namespace, yml)
    except Exception as e:
        print("Exception while creating sa %s " % e)

def hpe_read_cluster_role(name):
    try:
        obj = k8s_rbac_auth_v1.read_cluster_role(name)
        return obj
    except Exception as e:
        print("Exception while reading cluster role %s " % e)


def hpe_create_cluster_role(yml):
    try:
        k8s_rbac_auth_v1.create_cluster_role(yml)
    except Exception as e:
        print("Exception while creating cluster role %s " % e)

def hpe_read_cluster_role_binding(name):
    try:
        obj = k8s_rbac_auth_v1.read_cluster_role_binding(name)
        return obj
    except Exception as e:
        print("Exception while reading cluster role binding %s " % e)


def hpe_create_cluster_role_binding(yml):
    try:
        k8s_rbac_auth_v1.create_cluster_role_binding(yml)
    except Exception as e:
        print("Exception while creating cluster role binding %s " % e)


def hpe_read_role(name, namespace):
    try:
        obj = k8s_rbac_auth_v1.read_namespaced_role(name, namespace)
        return obj
    except Exception as e:
        print("Exception while reading sa %s " % e)


def hpe_create_role(yml, namespace):
    try:
        k8s_rbac_auth_v1.create_namespaced_role(namespace, yml)
    except Exception as e:
        print("Exception while creating sa %s " % e)


def hpe_read_role_binding(name, namespace):
    try:
        obj = k8s_core_v1.read_namespaced_role_binding(name, namespace)
        return obj
    except Exception as e:
        print("Exception while reading sa %s " % e)


def hpe_create_role_binding(yml, namespace):
    try:
        k8s_core_v1.create_namespaced_role_binding(namespace, yml)
    except Exception as e:
        print("Exception while creating sa %s " % e)


def hpe_read_statefulset(name, namespace):
    try:
        obj = k8s_extn_apps_v1.read_namespaced_stateful_set(name, namespace)
        return obj
    except Exception as e:
        print("Exception while reading sa %s " % e)


def hpe_create_statefulset(yml, namespace):
    try:
        k8s_extn_apps_v1.create_namespaced_stateful_set(namespace, yml)
    except Exception as e:
        print("Exception while creating sa %s " % e)


def create_sc(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "StorageClass":
                # print("PersistentVolume YAML :: %s" % el)
                print("\nCreating StorageClass...")
                obj = hpe_create_sc_object(el)
                print("\nStorageClass %s created." % obj.metadata.name)
    return obj


def create_pvc(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "PersistentVolumeClaim":
                # print("PersistentVolume YAML :: %s" % el)
                print("\nCreating PersistentVolumeClaim...")
                obj = hpe_create_pvc_object(el)
                print("\nPersistentVolumeClaim %s created." % obj.metadata.name)
    return obj


def create_pod(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "Pod":
                # print("Pod YAML :: %s" % el)
                print("\nCreating Pod...")
                obj = hpe_create_pod_object(el)
                print("\nPod %s created." % obj.metadata.name)
    return obj


def create_secret(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "Secret":
                # print("PersistentVolume YAML :: %s" % el)
                print("\nCreating Secret...")
                obj = hpe_create_secret_object(el)
                print("\nSecret %s created." % obj.metadata.name)
    return obj


def get_pvc_crd(pvc_name):
    try:
        print("\nReading CRD for %s " % pvc_name)
        command = "kubectl get hpevolumeinfos %s -o json" % pvc_name
        result = get_command_output_string(command)
        crd = json.loads(result)
        # print(crd)
        return crd
    except Exception as e:
        print("Exception %s while fetching crd for pvc %s " % (e, pvc_name))


def get_node_crd(node_name):
    try:
        print("\nReading CRD for %s " % node_name)
        command = "kubectl get hpenodeinfos %s -o json" % node_name
        result = get_command_output_string(command)
        crd = json.loads(result)
        # print(crd)
        return crd
    except Exception as e:
        print("Exception %s while fetching crd for node %s " % (e, node_name))


def get_pvc_volume(pvc_crd):
    vol_name = pvc_crd["spec"]["record"]["Name"]
    print("\nPVC %s has volume %s on array" % (pvc_crd["spec"]["uuid"], vol_name))
    return vol_name


def get_volume_from_array(hpe3par_cli, volume_name):
    try:
        print("\nFetching volume from array for %s " % volume_name)
        hpe3par_volume = hpe3par_cli.getVolume(volume_name)
        print("Volume from array :: %s " % hpe3par_volume)
        return hpe3par_volume
    except Exception as e:
        print("Exception %s while fetching volume from array for %s " % (e, volume_name))

def get_host_from_array(hpe3par_cli, host_name):
    try:
        print("\nFetching host details from array for %s " % host_name)
        hpe3par_host = hpe3par_cli.getHost(host_name)
        print("Host details from array :: %s " % hpe3par_host)
        return hpe3par_host
    except Exception as e:
        print("Exception %s while fetching host details from array for %s " % (e, host_name))




def verify_volume_properties(hpe3par_volume, **kwargs):
    print("In verify_volume_properties()")
    print("kwargs[provisioning] :: %s " % kwargs['provisioning'])
    print("kwargs[size] :: %s " % kwargs['size'])
    print("kwargs[compression] :: %s " % kwargs['compression'])
    print("kwargs[clone] :: %s " % kwargs['clone'])
    print("kwargs[snapcpg] :: %s " % kwargs['snapcpg'])
    print("kwargs[cpg] :: %s " % kwargs['cpg'])
    try:
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                if hpe3par_volume['provisioningType'] != 1:
                    print("provisioningType ")
                    return False
            elif kwargs['provisioning'] == 'tpvv':
                if hpe3par_volume['provisioningType'] != 2:
                    return False
            elif kwargs['provisioning'] == 'tdvv':
                if hpe3par_volume['provisioningType'] != 6 or hpe3par_volume['deduplicationState'] != 1:
                    return False

            if 'size' in kwargs:
                if hpe3par_volume['sizeMiB'] != int(kwargs['size']) * 1024:
                    return False
            else:
                if hpe3par_volume['sizeMiB'] != 102400:
                    return False

            if 'compression' in kwargs:
                if kwargs['compression'] == 'true':
                    if hpe3par_volume['compressionState'] != 1:
                        return False
                elif kwargs['compression'] == 'false':
                    if hpe3par_volume['compressionState'] != 2:
                        return False

            if 'clone' in kwargs:
                if "snapcpg" in kwargs:
                    if hpe3par_volume['snapCPG'] != kwargs['snapcpg']:
                        return False
                if hpe3par_volume['copyType'] != 1:
                    return False

            if 'cpg' in kwargs:
                if hpe3par_volume['userCPG'] != kwargs['cpg']:
                    return False
        return True
    except Exception as e:
        print("Exception while verifying volume properties %s " % e)


def verify_host_properties(hpe3par_host, **kwargs):
    print("In verify_host_properties()")
    encoding = "latin-1"
    print("kwargs[chapUser] :: %s " % kwargs['chapUser'])
    print("kwargs[chapPwd] :: %s " % kwargs['chapPassword'])
    try:
        if 'chapUser' in kwargs:
            if hpe3par_host['initiatorChapEnabled'] == True:
                if hpe3par_host['initiatorChapName'] == kwargs['chapUser'] and (base64.b64decode(hpe3par_host['initiatorEncryptedChapSecret'])).decode(encoding) == kwargs['chapPassword']:
                    return True
            else:
                return False
        return True
    except Exception as e:
        print("Exception while verifying host properties %s " % e)



def verify_volume_properties_3par(hpe3par_volume, **kwargs):
    print("In verify_volume_properties_3par()")
    if 'provisioning' in kwargs:
        print("kwargs[provisioning] :: %s " % kwargs['provisioning'])
    if 'size' in kwargs:
        print("kwargs[size] :: %s " % kwargs['size'])
    if 'compression' in kwargs:
        print("kwargs[compression] :: %s " % kwargs['compression'])
    if 'clone' in kwargs:
        print("kwargs[clone] :: %s " % kwargs['clone'])
    if 'snapcpg' in kwargs:
        print("kwargs[snapcpg] :: %s " % kwargs['snapcpg'])
    if 'cpg' in kwargs:
        print("kwargs[cpg] :: %s " % kwargs['cpg'])
    failure_cause = None
    try:
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                if 'compression' in kwargs and kwargs['compression'] == 'true':
                    if hpe3par_volume['provisioningType'] != 2:
                        failure_cause = 'provisioning'
                        return False, failure_cause
                else:
                    if hpe3par_volume['provisioningType'] != 1:
                        print("provisioningType ")
                        failure_cause = 'provisioning'
                        return False, failure_cause
            elif kwargs['provisioning'] == 'tpvv':
                if hpe3par_volume['provisioningType'] != 2:
                    failure_cause = 'provisioning'
                    return False, failure_cause
            elif kwargs['provisioning'] == 'dedup' or kwargs['provisioning'] == 'reduce':
                if hpe3par_volume['provisioningType'] != 6 or hpe3par_volume['deduplicationState'] != 1:
                    failure_cause = 'provisioning'
                    return False, failure_cause

            if 'size' in kwargs and kwargs['size'] is not None:
                size = kwargs['size']
                ind = None
                try:
                    ind = size.index('Gi')
                    size = size[0:ind]
                except Exception as e:
                    size = size
                # size = size[0:size.index('Gi')]
                if hpe3par_volume['sizeMiB'] != int(size) * 1024:
                    failure_cause = 'size'
                    return False, failure_cause
            else:
                if hpe3par_volume['sizeMiB'] != 19456:
                    failure_cause = 'size'
                    return False, failure_cause

            if kwargs['provisioning'] == 'tpvv' or kwargs['provisioning'] == 'dedup':
                print("########### kwargs['provisioning'] :: %s" % kwargs['provisioning'])
                if 'compression' in kwargs:
                    print("########### kwargs['compression'] :: %s" % kwargs['compression'])
                    print("########### hpe3par_volume['compressionState'] :: %s" % hpe3par_volume['compressionState'])
                    if kwargs['compression'] == 'true':
                        if hpe3par_volume['compressionState'] != 1:
                            failure_cause = 'compression'
                            return False, failure_cause
                    elif kwargs['compression'] == 'false' or kwargs['compression'] is None:
                        print("&&&&&&&&& i am here compression is :: %s" % kwargs['compression'])
                        print("hpe3par_volume['compressionState'] :: %s " % hpe3par_volume['compressionState'])
                        if hpe3par_volume['compressionState'] != 2:
                            print("########### FAILED!!!")
                            failure_cause = 'compression'
                            return False, failure_cause
            if kwargs['provisioning'] == 'reduce':
                if 'compression' in kwargs:
                    if hpe3par_volume['compressionState'] != 1:
                        failure_cause = 'compression'
                        return False, failure_cause
            elif 'provisioning' in kwargs and kwargs['provisioning'] == 'full':
                # for full provisioned volume can not be compressed
                if 'compression' in kwargs:
                    if kwargs['compression'] == 'true':
                        if hpe3par_volume['compressionState'] != 1:
                            failure_cause = 'compression'
                            return False, failure_cause
                    else:
                        if hpe3par_volume['compressionState'] != 4:
                            failure_cause = 'compression'
                            return False, failure_cause
            if 'clone' in kwargs:
                if "snapcpg" in kwargs:
                    if hpe3par_volume['snapCPG'] != kwargs['snapcpg']:
                        failure_cause = 'snapcpg'
                        return False, failure_cause
                if hpe3par_volume['copyType'] != 1:
                    failure_cause = 'clone'
                    return False, failure_cause

            if 'cpg' in kwargs:
                if hpe3par_volume['userCPG'] != kwargs['cpg']:
                    failure_cause = 'cpg'
                    return False, failure_cause
        return True, ""
    except Exception as e:
        print("Exception while verifying volume properties %s " % e)


def verify_volume_properties_primera(hpe3par_volume, **kwargs):
    try:
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                if hpe3par_volume['provisioningType'] != 1:
                    print("provisioningType ")
                    return False
            elif kwargs['provisioning'] == 'thin':
                if hpe3par_volume['provisioningType'] != 2:
                    return False
            elif kwargs['provisioning'] == 'dedup':
                if hpe3par_volume['provisioningType'] != 6 or hpe3par_volume['deduplicationState'] != 1:
                    return False

            if 'size' in kwargs:
                if hpe3par_volume['sizeMiB'] != int(kwargs['size']) * 1024:
                    return False
            else:
                if hpe3par_volume['sizeMiB'] != 102400:
                    return False

            if 'compression' in kwargs:
                if kwargs['compression'] == 'true':
                    if hpe3par_volume['compressionState'] != 1:
                        return False
                else:
                     if hpe3par_volume['compressionState'] != 2:
                         return False

            if 'clone' in kwargs:
                if "snapcpg" in kwargs:
                    if hpe3par_volume['snapCPG'] != kwargs['snapcpg']:
                        return False
                if hpe3par_volume['copyType'] != 1:
                    return False

            if 'cpg' in kwargs:
                if hpe3par_volume['userCPG'] != kwargs['cpg']:
                    return False
        return True
    except Exception as e:
        print("Exception while verifying volume properties %s " % e)


def delete_pvc(name):
    try:
        print("\nDeleting PVC %s..." % name)
        hpe_delete_pvc_object_by_name(name)
        flag = check_if_deleted(timeout, name, "PVC")
        if flag:
            print("\nPVC %s is deleted successfully" % name)
        return flag
    except Exception as e:
        print("Exception while deleting pvc %s :: %s" % (name, e))
        raise e


def verify_delete_volume_on_3par(hpe3par_cli, volume_name):
    try:
        print("\nVerify if volume is deleted from array for %s " % volume_name)
        hpe3par_volume = hpe3par_cli.getVolume(volume_name)
    except HTTPNotFound as e:
        print("\nVolume has been deleted from array for %s " % volume_name)
        return True
    except Exception as e:
        print("Exception while verifying volume deletion from array for %s :: %s" % (volume_name, e))
        raise e


def delete_sc(name):
    try:
        print("\nDeleting SC %s " % name)
        hpe_delete_sc_object_by_name(name)
        flag = check_if_deleted(timeout, name, "SC")
        if flag:
            print("\nSC %s is deleted" % name)
        return flag
    except Exception as e:
        print("Exception while deleting storage class :: %s" % e)
        raise e


def get_3par_cli_client(yml):
    print("\nIn get_3par_cli_client")
    array_4_x_list = ['15.213.71.140', '15.213.71.156']
    array_3_x_list = ['15.212.195.246', '10.50.3.21', '15.212.192.252']
    HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, PROTOCOL = read_array_prop(yml)
    port = None
    if HPE3PAR_IP in array_3_x_list:
        port = '8080'
    elif HPE3PAR_IP in array_4_x_list:
        port = '443'
    # HPE3PAR_API_URL = "https://" + HPE3PAR_IP + ":8080/api/v1"
    HPE3PAR_API_URL = "https://%s:%s/api/v1" % (HPE3PAR_IP, port)
    encoding = "utf-8"
    print("\nHPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                  HPE3PAR_IP,
                                                                                                  HPE3PAR_USERNAME,
                                                                                                  (base64.b64decode(
                                                                                                      HPE3PAR_PWD)).decode(
                                                                                                      encoding)))

    """logging.info("\nHPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                  HPE3PAR_IP,
                                                                                                  HPE3PAR_USERNAME,
                                                                                                  (base64.b64decode(
                                                                                                      HPE3PAR_PWD)).decode(
                                                                                                      encoding)))"""

    hpe3par_cli = _hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                             HPE3PAR_USERNAME, (base64.b64decode(HPE3PAR_PWD)).decode(encoding))
    return hpe3par_cli


def delete_secret(name, namespace):
    try:
        print("\nDeleting Secret %s from namespace %s..." % (name,namespace))
        hpe_delete_secret_object_by_name(name, namespace=namespace)
        flag = check_if_deleted(timeout, name, "Secret", namespace=namespace)
        if flag:
            print("\nSecret %s from namespace %s is deleted." % (name, namespace))
        return flag
    except Exception as e:
        print("Exception while deleting secret :: %s" % e)
        raise e


def verify_pod_node(hpe3par_vlun, pod):
    try:
        print("Verifying node where pod is mounted received from 3PAR and cluster are same...")
        pod_node_name = pod.spec.node_name
        dot_index = pod_node_name.find('.')
        if dot_index > 0:
            pod_node_name = pod_node_name[0:dot_index]
        print("Node from pod object :: %s " % pod_node_name)
        print("Node from array :: %s " % hpe3par_vlun['hostname'])
        return pod_node_name == hpe3par_vlun['hostname']
    except Exception as e:
        print("Exception while verifying node names where pod is mounted :: %s" % e)
        raise e


def get_3par_vlun(hpe3par_cli, volume_name):
    return hpe3par_cli.getVLUN(volume_name)


def get_iscsi_ips(hpe3par_cli):
    iscsi_info = hpe3par_cli.getiSCSIPorts(state=4)
    iscsi_ips = []
    for entry in iscsi_info:
        iscsi_ips.append(entry['IPAddr'])
    return iscsi_ips


def verify_by_path(iscsi_ips, node_name):
    disk_partition = []
    try:
        flag = True
        # verify ls -lrth /dev/disk/by-path at node
        print("Verifying output of ls -lrth /dev/disk/by-path...")
        for ip in iscsi_ips:
            print("== For IP::%s " % ip)
            command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-[0-9]*$))$/ {print $NF}' | awk -F'../' '{print $NF}'"
            print("command is %s " % command)
            partitions = get_command_output(node_name, command)
            print("== Partition(s) received for %s are %s" % (ip, partitions))
            if partitions is None or len(partitions) <= int(0):
                flag = False
                break

            for partition in partitions:
                disk_partition.append(partition)
            # print("Partition name %s" % partitions)

        return flag, disk_partition
    except Exception as e:
        print("Exception while verifying partitions for iscsi ip(s) :: %s" % e)
        raise e


def verify_multipath(hpe3par_vlun, disk_partition):
    print("\n########################### verify_multipath ###########################")
    try:
        vv_wwn = hpe3par_vlun['volumeWWN']
        node_name = hpe3par_vlun['hostname']

        print("Fetching DM(s)...")
        # fetch dm from /dev/mapper
        # command = "ls -ltrh /dev/mapper/ | awk -v IGNORECASE=1 '$9~/^[0-9]" + vv_wwn.upper() + "/ {print$NF}' | awk -F'../' '{print$NF}'"
        command = "ls -lrth /dev/disk/by-id/ | awk -v IGNORECASE=1 '$9~/^dm-uuid-mpath-[0-9]" + vv_wwn + \
                  "/' | awk -F '../../' '{print$NF}'"
        print("dev/mapper command to get dm :: %s " % command)
        dm = get_command_output(node_name, command)
        print("DM(s) received :: %s " % dm)

        # Fetch user friendly multipath name
        print("Fetching user friendly multipath name")
        command = "ls -lrth /dev/mapper/ | awk '$11~/" + dm[0] + "$/' | awk '{print$9}'"
        mpath_name = get_command_output(node_name, command)
        print("mpath received :: %s " % mpath_name)

        print("Verifying multipath -ll output...")
        # Verify multipath -ll output
        command = "sudo multipath -ll | awk -v IGNORECASE=1 '/^" + mpath_name[
            0] + "\s([0-9]" + vv_wwn + ")*/{x=NR+4}(NR<=x){print}'"

        # import pytest;
        # pytest.set_trace()

        print("multipath -ll command to :: %s " % command)
        paths = get_command_output(node_name, command)
        print("multipath output ::%s \n\n" % paths)
        index = 0
        multipath_failure_flag = 0
        disk_partition_temp = None
        disk_partition_temp = disk_partition.copy()
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
                    multipath_failure_flag += 1

        print("disk_partition_temp :: %s " % disk_partition_temp)
        print("disk_partition :: %s " % disk_partition)
        return multipath_failure_flag != 0, disk_partition_temp
    except Exception as e:
        print("Exception while verifying multipath :: %s" % e)
        raise e


def verify_partition(disk_partition_temp):
    try:
        return len(disk_partition_temp) == 0
    except Exception as e:
        print("Exception while verifying partitions :: %s" % e)
        raise e


def verify_lsscsi(node_name, disk_partition):
    try:
        # Verify lsscsi output
        command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
        print("lsscsi command :: %s " % command)
        partitions = get_command_output(node_name, command)

        print("partitions after lsscsi %s " % partitions)
        print("partitions from by-path %s " % disk_partition)
        return partitions.sort() == disk_partition.sort()
    except Exception as e:
        print("Exception while verifying lsscsi :: %s" % e)
        raise e


def delete_pod(name, namespace):
    try:
        print("Deleting pod %s..." % name)
        hpe_delete_pod_object_by_name(name, namespace=namespace)

        return check_if_deleted(timeout, name, "Pod", namespace=namespace)
        print("Pod %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting pod :: %s" % e)
        raise e


def verify_deleted_partition(iscsi_ips, node_name):
    try:
        failed_for_ip = None
        flag = True
        print("Verifying 'ls -lrth /dev/disk/by-path' entries are cleaned...")
        # verify ls -lrth /dev/disk/by-path at node
        for ip in iscsi_ips:
            print("For IP::%s " % ip)
            command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-0))$/ {print $NF}' | awk -F'../' '{print $NF}'"
            print("command is %s " % command)
            partitions = get_command_output(node_name, command)
            if len(partitions) != int(0):
                flag = False
                failed_for_ip = ip
                break
        return flag, failed_for_ip
    except Exception as e:
        print("Exception while verifying deleted by-path:: %s" % e)
        raise e


def verify_deleted_multipath_entries(node_name, hpe3par_vlun):
    try:
        # Verify multipath -ll output
        command = "multipath -ll | awk -v IGNORECASE=1 '/^([0-9]" + hpe3par_vlun['volumeWWN'] + \
                  ").*(3PARdata,VV)/{x=NR+4}(NR<=x){print}'"
        # print("multipath -ll command to :: %s " % command)
        paths = get_command_output(node_name, command)
        return paths
    except Exception as e:
        print("Exception :: %s" % e)
        raise e


def verify_deleted_lsscsi_entries(node_name, disk_partition):
    try:
        flag = True
        print("Verifying 'lsscsi' entries are cleaned...")
        #import pytest;
        #pytest.set_trace()
        # Verify lsscsi output
        command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
        partitions = get_command_output(node_name, command)
        print("partitions in lsscsi after pod deletion %s " % partitions)
        print("disk_partition before pod deletion %s " % disk_partition)
        for org_partition in disk_partition:
            print(org_partition)
            if org_partition in partitions:
                flag = False
                print("Partition %s still exists after pod deletion" % org_partition)
                break

        return flag

        """if partitions.sort() == disk_partition.sort():
            return True
        else:
            return False"""
        # return partitions.sort() == disk_partition.sort()
        # return partitions
    except Exception as e:
        print("Exception :: %s" % e)
        raise e


def verify_clone_crd_status(pvc_volume_name):
    try:
        time = 0
        flag = True
        while True:
            crd_pvc = get_pvc_crd(pvc_volume_name)
            if "Status" in crd_pvc["spec"]["record"]:
                if crd_pvc["spec"]["record"]["Status"] == "Completed":
                    break
            if int(time) > int(timeout):
                flag = False
                break
            time += 1
            sleep(1)
        return flag
    except Exception as e:
        print("Exception while verifying CRD for clone pvc  :: %s" % e)
        raise e


def get_kind_name(yml, kind_name):
    # Fetch snapclass name
    snapclass_name = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            print(el)
            if el['kind'] == kind_name:
                print(el['kind'])
                snapclass_name = el['metadata']['name']
                break
    return snapclass_name


def create_snapclass(yml, snap_class_name='ci-snapclass'):
    try:
        print("Creating snapclass %s..." % snap_class_name)
        command = "kubectl create -f " + yml
        output = get_command_output_string(command)
        if str(output) == "volumesnapshotclass.snapshot.storage.k8s.io/%s created\n" % snap_class_name:
            print("Snapclass %s created." % snap_class_name)
            return True
        else:
            print("Snapclass %s is not created." % snap_class_name)
            return False
    except Exception as e:
        print("Exception while creating snapclass :: %s" % e)
        raise e


def verify_snapclass_created(snap_class_name='ci-snapclass'):
    try:
        print("Verify if snapclass %s is created..." % snap_class_name)
        command = "kubectl get volumesnapshotclasses.snapshot.storage.k8s.io -o json"
        output = get_command_output_string(command)
        flag = False
        crds = json.loads(output)
        print(crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                print(snap_class["metadata"]["name"])
                if str(snap_class["metadata"]["name"]) == snap_class_name:
                    flag = True
        return flag
    except Exception as e:
        print("Exception while verifying snapclass :: %s" % e)
        raise e


def create_snapshot(yml, snapshot_name='ci-pvc-snapshot'):
    try:
        print("Creating snapshot %s ..." % snapshot_name)
        command = "kubectl create -f " + yml
        output = get_command_output_string(command)
        if str(output) == "volumesnapshot.snapshot.storage.k8s.io/%s created\n" % snapshot_name:
            return True
        else:
            return False
    except Exception as e:
        print("Exception while creating snapshot :: %s" % e)
        raise e


def verify_snapshot_created(snapshot_name='ci-pvc-snapshot'):
    try:
        print("Verifying snapshot %s created..." % snapshot_name)
        command = "kubectl get volumesnapshots.snapshot.storage.k8s.io -o json"
        output = get_command_output_string(command)
        flag = False
        crds = json.loads(output)
        print(crds)
        if crds["kind"] == "List":
            snapshots = crds["items"]
            for snapshot in snapshots:
                print(snapshot["metadata"]["name"])
                if str(snapshot["metadata"]["name"]) == snapshot_name:
                    flag = True
        return flag
    except Exception as e:
        print("Exception while verifying snapshot :: %s" % e)
        raise e


def verify_snapshot_ready(snapshot_name='ci-pvc-snapshot'):
    try:
        snap_uid = None
        print("Verify if snapshot is ready...")
        command = "kubectl get volumesnapshots.snapshot.storage.k8s.io %s -o json" % snapshot_name
        print(command)
        flag = False
        time = 0
        while True:
            output = get_command_output_string(command)
            crd = json.loads(output)
            if "status" in crd and "readyToUse" in crd["status"]:
                if crd["status"]["readyToUse"] is True:
                    flag = True
                    snap_uid = crd["metadata"]["uid"]
                    break
            print(".", end='', flush=True)
            if int(time) > int(timeout):
                flag = False
                break
            time += 1
            sleep(1)

        return flag, snap_uid
    except Exception as e:
        print("Exception while verifying snapshot status :: %s" % e)
        raise e


def verify_snapshot_on_3par(hpe3par_volume, volume_name):
    try:
        flag = True
        message = None
        if hpe3par_volume['provisioningType'] != 3:
            flag = False
            message = "Snapshot volume provision is not correct"
        if hpe3par_volume['copyType'] != 3:
            flag = False
            message = "Snapshot volume type is not vcopy"
        if hpe3par_volume['copyOf'] != volume_name:
            flag = False
            message = "Snapshot volume base volume mismatch"
        return flag, message
    except Exception as e:
        print("Exception while verifying snapshot volume on 3par :: %s" % e)
        raise e


def delete_snapshot(snapshot_name='ci-pvc-snapshot'):
    try:
        print("Deleting snapshot %s..." % snapshot_name)
        command = "kubectl delete volumesnapshots.snapshot.storage.k8s.io %s" % snapshot_name
        output = get_command_output_string(command)
        print(output)
        if str(output) == 'volumesnapshot.snapshot.storage.k8s.io "%s" deleted\n' % snapshot_name:
            return True
        else:
            return False
    except Exception as e:
        print("Exception while verifying snapshot deletion :: %s" % e)
        raise e


def verify_snapshot_deleted(snapshot_name='ci-pvc-snapshot'):
    try:
        print("Verify if snapshot %s is deleted..." % snapshot_name)
        command = "kubectl get volumesnapshots.snapshot.storage.k8s.io -o json"
        output = get_command_output_string(command)
        flag = False
        crds = json.loads(output)
        # print("crds :: %s " % crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                if snap_class["metadata"]["name"] == snapshot_name:
                    flag = True
        return flag
    except Exception as e:
        print("Exception while verifying snapshot deletion :: %s" % e)
        raise e


def delete_snapclass(snapclass_name='ci-snapclass'):
    try:
        print("Deleting snapshot-class %s...")
        command = "kubectl delete volumesnapshotclasses %s" % snapclass_name
        output = get_command_output_string(command)
        print(output)
        if str(output) == 'volumesnapshotclass.snapshot.storage.k8s.io "%s" deleted\n' % snapclass_name:
            return True
        else:
            return False
    except Exception as e:
        print("Exception while verifying snapclass deletion :: %s" % e)
        raise e


def verify_snapclass_deleted(snapclass_name='ci-snapclass'):
    try:
        print("Verify if snapshot-class %s is deleted..." % snapclass_name)
        command = "kubectl get volumesnapshotclasses -o json"
        output = get_command_output_string(command)
        flag = False
        crds = json.loads(output)
        print("crds :: %s " % crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                if snap_class["metadata"]["name"] == snapclass_name:
                    flag = True
        return flag
    except Exception as e:
        print("Exception while verifying snapclass crd deletion :: %s" % e)
        raise e


def verify_crd_exists(crd_name, crd_type):
    try:
        #print("Verifying if CRD for %s is deleted..." % crd_name)
        flag = False
        command = "kubectl get %s -o json" % crd_type
        #print(command)
        output = get_command_output_string(command)
        crds = json.loads(output)
        #print("crds :: %s " % crds)
        if crds["kind"] == "List":
            crd_objs = crds["items"]
            for crd_obj in crd_objs:
                # print(crd_obj["metadata"]["name"])
                if str(crd_obj["metadata"]["name"]) == crd_name:
                    flag = True
                    break
        return flag
    except Exception as e:
        print("Exception while verifying CRD for clone pvc  :: %s" % e)
        raise e


def check_if_crd_deleted(crd_name, crd_type):
    try:
        time = 0
        flag = True

        while True:
            if verify_crd_exists(crd_name, crd_type) is False:
                break

            if int(time) > int(timeout):
                print("\nCRD %s of %s is not deleted yet. Taking longer..." % (crd_name, crd_type))
                flag = False
                break
            print(".", end='', flush=True)
            time += 1
            sleep(1)

        return flag
    except Exception as e:
        print("Exception %s while verifying if CRD %s of %s is deleted  :: %s" % (e, crd_name, crd_type))
        raise e


def verify_pvc_crd_published(crd_name):
    try:
        print("Verifying if PVC CRD is publish/unpublished...")
        #logging.info("Verifying if PVC CRD is publish/unpublished...")
        flag = False
        crd = get_pvc_crd(crd_name)
        print("crd :: %s " % crd)
        if crd is not None:
            if "spec" in crd and "record" in crd["spec"] and "Published" in crd["spec"]["record"]:
                if crd["spec"]["record"]["Published"] == "true":
                    flag = True
                else:
                    flag = False
        return flag
    except Exception as e:
        print("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        #logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def verify_node_crd_chap(crd_name, **kwargs):
    try:
        print("Verifying chap details in node crd")
        encoding = "utf-8"        
        flag = False
        crd = get_node_crd(crd_name)
        print("crd :: %s " % crd)
        if crd is not None:
            if 'chapUser' in kwargs:
                assert crd['spec']['chap_user'] == kwargs['chapUser']
                assert (base64.b64decode(crd['spec']['chap_password'])).decode(encoding) == kwargs['chapPassword']
                flag = True
                return flag 
        return flag
    except Exception as e:
        print("Exception %s while verifying if node CRD %s :: %s" % (e, crd_name))
        raise e




def get_array_version(hpe3par_cli):
    try:
        sysinfo = hpe3par_cli.getStorageSystemInfo()
        return sysinfo['systemVersion']

    except Exception as e:
        print("Exception %s while fetching arra version :: %s" % e)
        #logging.error("Exception %s while fetching arra version :: %s" % e)
        raise e


def patch_pvc(name, namespace, patch_json):
    try:
        print("patch_json :: %s " % patch_json)
        response = k8s_core_v1.patch_namespaced_persistent_volume_claim(name, namespace, patch_json)
        print(response)
        return response
    except Exception as e:
        print("Exception while patch PVC %s\n%s" % (name, e))
        #logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def is_test_passed(array_version, status, is_cpg_ssd, provisioning, compression):
    print("array_version :: %s " % array_version[0:3])
    print("status :: %s " % status)
    print("is_cpg_ssd :: %s " % is_cpg_ssd)
    print("provisioning :: %s " % provisioning)
    print("compression :: %s " % compression)
    #comp_flag = compression is None
    #print("compression is None :: %s " % comp_flag)
    if provisioning is not None:
        if provisioning.lower() == 'true':
            provisioning = True
        elif provisioning.lower() == 'false':
            provisioning = False
        else:
            provisioning = provisioning.lower()

    if compression is not None:
        if compression.lower() == 'true':
            compression = True
        elif compression.lower() == 'false':
            compression = False
        else:
            compression = compression.lower()

    """if is_cpg_ssd is not None:
        if is_cpg_ssd.lower() == 'true':
            is_cpg_ssd = True
        elif is_cpg_ssd.lower() == 'false':
            is_cpg_ssd = False
        else:
            is_cpg_ssd = is_cpg_ssd.lower"""

    if array_version[0:3] == '3.3':
        if provisioning == 'tpvv':
            if is_cpg_ssd is True:
                if compression is True or compression is False or compression is None:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        return False
                else:
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
            else:
                if compression is False or compression is None:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        print("******* returning false")
                        return False
                else:
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
        elif provisioning == 'full':
            if is_cpg_ssd is True:
                if compression == '':
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
                else:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        print("******* returning false")
                        return False
            else:
                if compression == '' or compression is True:
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
                else:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        print("******* returning false")
                        return False
        elif provisioning == 'dedup':
            if is_cpg_ssd is True:
                if compression == '':
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
                else:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        return False
            else:
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
    elif array_version[0:3] == '4.1' or array_version[0:3] == '4.2':
        print("arrays version is :: %s" % array_version[0:3])
        print("provisioning :: %s" % provisioning)
        print("compression :: %s" % compression)
        print("is_cpg_ssd :: %s" % is_cpg_ssd)
        if provisioning == 'tpvv':
            if compression is True or compression == '':
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
            else:
                if status == 'ProvisioningSucceeded':
                    return True
                else:
                    return False
        elif provisioning == 'full':
            if status == 'ProvisioningFailed':
                return True
            else:
                return False
        elif provisioning == 'reduce':
            if is_cpg_ssd is True:
                if compression == '':
                    if status == 'ProvisioningFailed':
                        return True
                    else:
                        return False
                else:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        print("111")
                        return False
            else:
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False


def get_sc_properties(yml):
    try:
        provisioning = None
        compression = None
        cpg_name = None
        size = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    if 'provisioning_type' in el['parameters']:
                        provisioning = el['parameters']['provisioning_type']
                    if 'compression' in el['parameters']:
                        compression = el['parameters']['compression']
                    if 'cpg' in el['parameters']:
                        cpg_name = el['parameters']['cpg']
                    if 'size' in el['parameters']:
                        size = el['parameters']['size']
        print("provisioning :: %s, compression :: %s, cpg_name :: %s" % (provisioning, compression, cpg_name))
        return provisioning, compression, cpg_name, size
    except Exception as e:
        print("Exception in get_sc_properties :: %s" % e)
        raise e


def check_status_from_events(kind, name, namespace, uid):
    try:
        status = None
        message = None
        got_status = None
        while True:
            if got_status is True:
                break
            # events_list = k8s_core_v1.list_event_for_all_namespaces()
            command = "kubectl get events --sort-by='{.metadata.creationTimestamp}' -o json"
            # print(command)
            output = get_command_output_string(command)
            events_json = json.loads(output)
            if events_json["kind"] == "List":
                event_list_from_json = events_json["items"]
                event_list = event_list_from_json[::-1]
                for event in event_list:
                    if event['involvedObject']['kind'] == kind and event['involvedObject']['name'] == name and \
                            event['involvedObject']['namespace'] == namespace and event['involvedObject']['uid'] == uid:
                        print("\n%s" % event)
                        if event['reason'] in ['ProvisioningSucceeded', 'ProvisioningFailed']:
                            print("uid :: %s " % event['involvedObject']['uid'])
                            status = event['reason']
                            message = event['message']
                            got_status = True
                            break
        return status, message
    except Exception as e:
        print("Exception in check_status_from_events for %s/%s in %s:: %s" % (kind, name, namespace, e))
        raise e


def check_cpg_prop_at_array(hpe3par_cli, cpg_name, property):
    try:
        cpg = hpe3par_cli.getCPG(cpg_name)
        if property == 'ssd':
            disk_type = None
            if 'SAGrowth' in cpg and 'LDLayout' in cpg['SAGrowth'] and 'diskPatterns' in cpg['SAGrowth']['LDLayout']:
                disk_patterns = cpg['SAGrowth']['LDLayout']['diskPatterns']
                for item in disk_patterns:
                    if 'diskType' in item:
                        disk_type = item['diskType']
                        break
            elif 'SDGrowth' in cpg and 'LDLayout' in cpg['SDGrowth'] and 'diskPatterns' in cpg['SDGrowth']['LDLayout']:
                disk_patterns = cpg['SDGrowth']['LDLayout']['diskPatterns']
                for item in disk_patterns:
                    if 'diskType' in item:
                        disk_type = item['diskType']
                        break
            if disk_type == 3:
                return True
            else:
                return False
    except Exception as e:
        print("Exception in check_cpg_prop_at_array for %s:: %s" % (cpg_name, e))
        raise e


def get_pod_node(yml):
    try:
        node_name = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "Pod":
                    if 'nodeName' in el['spec']:
                        node_name = el['spec']['nodeName']

        print("node_name :: %s" % node_name)
        return node_name
    except Exception as e:
        print("Exception in get_pod_node :: %s" % e)
        raise e


def create_pvc_bulk(yml):
    pvc_map = {}
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        print("\nCreating %s PersistentVolumeClaim..." % len(elements))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "PersistentVolumeClaim":
                obj = hpe_create_pvc_object(el)
                pvc_map[obj.metadata.name] = obj
    print("PVCs created are :: %s " % pvc_map)
    return pvc_map


def check_status_for_bulk(kind, map):
    obj_list = map.values()
    obj_by_status_map = {}
    expected_status = 'Bound'
    if kind.lower() == 'pvc' or kind.lower() == 'PersistentVolumeClaim'.lower():
        expected_status = 'ProvisioningSucceeded'
    for obj in obj_list:
        status, message = check_status_from_events(obj.kind, obj.name, obj.metadata.namespace, obj.metadata.uid)
        if status in obj_by_status_map:
            obj_by_status_map[status].append(obj)
        else:
            obj_by_status_map[status] = [obj]
    return obj_by_status_map


def get_details_for_volume(yml):
    yaml_values = {}
    try:
        vol_name = None
        cpg = None
        provisioning = None
        compression = None
        comment = None
        size = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "auto_data":
                    yaml_values['vol_name'] = el['vol_name']
                    yaml_values['cpg'] = el['cpg']
                    yaml_values['cpg'] = el['cpg']
                    yaml_values['provisioning'] = el['provisioning_type']
                    if 'snapCPG' in el:
                        yaml_values['snapCPG'] = el['snapCPG']
                    if 'comment' in el:
                        yaml_values['comment'] = el['comment']
                    if 'compression' in el:
                        yaml_values['compression'] = el['compression']
                    if 'size' in el:
                        yaml_values['size'] = el['size']
                    """vol_name = el['vol_name']
                    cpg = el['cpg']
                    provisioning = el['provisioning_type']
                    if 'compression' in el:
                        compression = el['compression']
                    if 'comment' in el:
                        comment = el['comment']
                    if 'size' in el:
                        size = el['size']"""
        """print("vol_name :: %s, cpg :: %s, provisioning :: %s, compression :: %s, comment :: %s, size :: %s" %
              (vol_name, cpg, provisioning, compression, comment, size))
        return vol_name, cpg, provisioning, compression, comment, size"""

        size = 10240
        if 'size' in yaml_values.keys():
            size = yaml_values['size']
            if size[-1].lower() == 'g'.lower():
                size = int(size[:-1]) * 1024
            elif size[-2:].lower() == 'gi'.lower():
                size = int(size[:-2]) * 1024
        yaml_values['size'] = size
        print(yaml_values)
        return yaml_values
    except Exception as e:
        print("Exception in get_details_for_volume:: %s" % e)
        raise e
