import yaml
from kubernetes import client, config
from time import sleep
from hpe3parclient.client import HPE3ParClient

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
        resp = obj = k8s_core_v1.create_namespaced_secret(namespace="kube-system", body=yml)
        print("Storage Class created. status=%s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e

def hpe_create_pvc_object(yml):
    try:
        pvc = k8s_core_v1.create_namespaced_persistent_volume_claim(namespace="default", body=yml)
        # print("PVC created. status=%s" % pvc.status.phase)
        return pvc
    except client.rest.ApiException as e:
         print("Exception :: %s" % e)
         raise e


def hpe_read_pvc_object(pvc_name):
    try:
        pvc = k8s_core_v1.read_namespaced_persistent_volume_claim(pvc_name, namespace="default")
        return pvc
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def hpe_delete_pvc_object_by_name(pvc_name):
    try:
        pvc = k8s_core_v1.delete_namespaced_persistent_volume_claim(pvc_name, namespace="default")
    except client.rest.ApiException as e:
        print("Exception while deleting pvc:: %s" % e)
        raise e


def hpe_delete_secret_object_by_name(secret_name):
    try:
        pvc = k8s_core_v1.delete_namespaced_secret(secret_name, namespace="kube-system")
    except client.rest.ApiException as e:
        print("Exception while deleting secret:: %s" % e)
        raise e


def hpe_delete_sc_object_by_name(sc_name):
    try:
        pvc = k8s_storage_v1.delete_storage_class(sc_name)
    except client.rest.ApiException as e:
        print("Exception while deleting sc:: %s" % e)
        raise e


def hpe_list_pvc_objects():
    try:
        pvc_list = k8s_core_v1.list_namespaced_persistent_volume_claim(namespace="default")
        return pvc_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e

def hpe_list_pvc_objects_names():
    try:
        pvc_names = []
        pvc_list = hpe_list_pvc_objects()
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


def hpe_list_secret_objects():
    try:
        secret_list = k8s_core_v1.list_namespaced_secret(namespace="kube-system")
        return secret_list
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e

def hpe_list_secret_objects_names():
    try:
        secret_names = []
        secret_list = hpe_list_secret_objects()
        for secret in secret_list.items:
            secret_names.append(secret.metadata.name)

        return secret_names
    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e


def check_if_deleted(timeout, name, kind):
    time = 0
    flag = True

    # print("timeout :: %s" % timeout)
    # print("name :: %s" % name)
    # print("kind :: %s" % kind)

    while True:
        if kind == 'PVC':
            obj_list = hpe_list_pvc_objects_names()
        elif kind == 'SC':
            obj_list = hpe_list_sc_objects_names()
        elif kind == 'Secret':
            obj_list = hpe_list_secret_objects_names()
        else:
            print("Not a supported kind")
            flag = False
            break
        # print(obj_list)
        print".",
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
