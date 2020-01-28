import yaml
from kubernetes import client, config

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

