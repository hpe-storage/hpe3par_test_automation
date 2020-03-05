import yaml
from kubernetes import client, config
from time import sleep
from hpe3parclient.client import HPE3ParClient
import paramiko

config.load_kube_config()
k8s_storage_v1 = client.StorageV1Api()
k8s_core_v1 = client.CoreV1Api()
k8s_apps_v1 = client.ExtensionsV1beta1Api()


def hpe_create_sc_object(yml):
    try:
        resp = k8s_storage_v1.create_storage_class(body=yml)
        print("Storage Class created. status=%s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_create_secret_object(yml):
    try:
        namespace = "default"
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
            print("In if :: %s " % namespace)
        print("Out of if :: %s " % namespace)
        resp = obj = k8s_core_v1.create_namespaced_secret(namespace=namespace, body=yml)
        print("Storage Class created. status=%s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
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
        sc_list = hpe_list_pvc_objects()
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
        print("kwargs :: keys :: %s,\n values :: %s" % (kwargs.keys(), kwargs.values()))
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
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "Secret":
                    HPE3PAR_IP = el['stringData']['backend']
                    HPE3PAR_USERNAME = el['stringData']['username']
                    HPE3PAR_PWD = el['data']['password']
        print("HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD))
        return HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e

def _hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD):
    # Login to 3Par array and initialize connection for WSAPI calls
    hpe_3par_cli = HPE3ParClient(HPE3PAR_API_URL, True, False, None, True)
    hpe_3par_cli.login(HPE3PAR_USERNAME, HPE3PAR_PWD)
    hpe_3par_cli.setSSHOptions(HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD)
    return hpe_3par_cli

def check_status(timeout, name, kind, status, namespace="default"):
    time = 0
    flag = True
    # print("timeout :: %s" % timeout)
    # print("time :: %s" % time)
    # print("kind :: %s" % kind)
    # print("status :: %s" % status)

    while True:
        obj = ""
        if kind == 'pv':
            obj = k8s_core_v1.read_persistent_volume(name)
        elif kind == 'pvc':
            obj = k8s_core_v1.read_namespaced_persistent_volume_claim(name, namespace)
        elif kind == 'pod':
            obj = k8s_core_v1.read_namespaced_pod(name, namespace)
        elif kind == 'deployment':
            obj = k8s_apps_v1.read_namespaced_deployment(name, namespace)
            print(obj)
        else:
            print("Not a supported kind")
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

        if int(time) > int(timeout):
            print("\n%s not yet in %s state. Taking longer than expected..." % (kind, status))
            # print("obj :: %s" % obj)
            flag = False
            break
        time += 1
        sleep(1)

    return flag,obj

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

