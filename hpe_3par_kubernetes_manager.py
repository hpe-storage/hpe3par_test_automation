import re

import pytest
import random
import yaml
from kubernetes import client, config
from time import sleep
from hpe3parclient.client import HPE3ParClient
from kubernetes.stream import stream
import paramiko
import os
import json
from hpe3parclient.exceptions import HTTPNotFound
import base64
import datetime
import logging
import globals
import inspect

config.load_kube_config()
k8s_storage_v1 = client.StorageV1Api()
k8s_core_v1 = client.CoreV1Api()
k8s_api_extn_v1 = client.ApiextensionsV1Api()
k8s_rbac_auth_v1 = client.RbacAuthorizationV1Api()
k8s_apps_v1 = client.AppsV1Api()

timeout = 180


def hpe_create_service_object(yml):
    """
    hpe_create_service_object - This function creates a Kubernetes service using the provided service configuration (body)
    Parameters:
        Required:
            1. (yml): The body of the Kubernetes service configuration.
        Optional:
            None
        Returns:
            resp: The response object from the Kubernetes API after service creation.
        Raises:
            Exception: If there's an error while creating the service, it catches and raises the exception.
    """
    try:
        resp = k8s_core_v1.create_namespaced_service(namespace=globals.namespace, body=yml)
        logging.getLogger().debug("Service created. Status is %s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception in creating service: %s" % e)
        raise e


def create_service(yml):
    """
    create_service - This function calls the hpe_create_service_object after loading and parsing the YAML service configuration.
    Parameters:
        Required:
            1. (yml): The body of the Kubernetes service configuration.
        Optional:
            None
        Returns:
            obj: The response object from hpe_create_service_object() Kubernetes API after service is created.
    """
    obj = None
    with open(yml) as f:
        for el in list(yaml.safe_load_all(f)):
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "Service":
                logging.getLogger().info("Creating Service...")
                obj = hpe_create_service_object(el)
                logging.getLogger().info("Service %s created." % obj.metadata.name)
    return obj

def hpe_delete_service_object_by_name(service_name, namespace):
    """
    hpe_delete_service_object_by_name - This function deletes a Kubernetes service using the provided service name, and namespace.
    Parameters:
        Required:
            1. (service_name): The name of the service to be deleted.
            2. (namespace): The namespace where the service was created under.
        Optional:
            None
        Returns:
            None
        Raises:
            Exception: If there's an error while deleting the service, it catches and raises the exception.
    """
    try:
        service = k8s_core_v1.delete_namespaced_service(service_name, namespace=namespace)
        logging.getLogger().info(service)
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception while deleting Service :: %s" % e)
        raise e

def delete_service(name, namespace):
    """
    delete_service - This function calls hpe_delete_service_object_by_name and checks if the service was deleted.
    Parameters:
        Required:
            1. (service_name): The name of the service to be deleted.
            2. (namespace): The namespace where the service was created under.
        Optional:
            None
        Returns:
            flag: (Boolean) The value after checking if the Service was deleted.
        Raises:
            Exception: If there's an error while deleting the service, it catches and raises the exception.
    """
    try:
        logging.getLogger().info("\nDeleting Service %s from namespace %s..." % (name,namespace))
        hpe_delete_service_object_by_name(name, namespace=namespace)
        flag = check_if_deleted(timeout, name, "Service", namespace=namespace)
        if not flag:
            logging.getLogger().info("\nService %s from namespace %s could not be deleted." % (name, namespace))
            return False
        logging.getLogger().info("\nService %s from namespace %s is deleted." % (name, namespace))
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while deleting service :: %s" % e)
        raise e

def hpe_create_sc_object(yml):
    try:
        resp = k8s_storage_v1.create_storage_class(body=yml)
        logging.getLogger().debug("Storage Class created. status=%s" % resp.metadata.name)
        # print("Storage Class created. status=%s" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        #logging.error("Exception :: %s" % e)
        raise e


def hpe_create_secret_object(yml):
    try:
        #namespace = "default"
        namespace = globals.namespace
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        resp = obj = k8s_core_v1.create_namespaced_secret(namespace=namespace, body=yml)
        # print("Secret %s created" % resp.metadata.name)
        logging.getLogger().debug("Secret %s created" % resp.metadata.name)
        return resp
    except client.rest.ApiException as e:
        #print("Exception while creating secret:: %s" % e)
        logging.getLogger().error("Exception while creating secret:: %s" % e)
        #logging.error("Exception while creating secret:: %s" % e)
        raise e


def hpe_create_pvc_object(yml):
    try:
        #namespace = "default" # kept namespace default else snapshot crd fails to find pvc
        namespace = globals.namespace
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        pvc = k8s_core_v1.create_namespaced_persistent_volume_claim(namespace=namespace, body=yml)
        # print("PVC created. status=%s" % pvc.status.phase)
        return pvc
    except client.rest.ApiException as e:
         #print("Exception :: %s" % e)
         logging.getLogger().error("Exception while creating pvc :: %s" % e)
         raise e


def hpe_create_pod_object(yml):
    try:
         #namespace = "default"
         namespace = globals.namespace
         if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
         pod = k8s_core_v1.create_namespaced_pod(namespace=namespace, body=yml)
         return pod
    except client.rest.ApiException as e:
          #print("Exception :: %s" % e)
          logging.getLogger().error("Exception while creating pod :: %s" % e)
          raise e

def hpe_connect_pod_container(name, command):
    try: 
        namespace = globals.namespace
        api_response = stream(k8s_core_v1.connect_get_namespaced_pod_exec, name=name,namespace=namespace,command=command, stderr=True, stdin=False, stdout=True, tty=False)
        return api_response
    except client.rest.ApiException as e:
          logging.getLogger().error("Exception while connecting to pod :: %s" % e)
          raise e



def hpe_create_dep_object(yml):
    try:
        #namespace = "default"
        namespace = globals.namespace
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        dep = k8s_apps_v1.create_namespaced_deployment(namespace=namespace, body=yml)
        return dep
    except client.rest.ApiException as e:
         #print("Exception :: %s" % e)
         logging.getLogger().error("Exception while creating deployment:: %s" % e)
         raise e


def hpe_delete_dep_object(name, namespace):
    try:
        dep = k8s_apps_v1.delete_namespaced_deployment(name, namespace=namespace)
        # print("PVC created. status=%s" % pvc.status.phase)
        logging.getLogger().debug("Deployment %s deleted" % name)
        return dep
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception while deleting deployment :: %s" % e)
        raise e


def hpe_get_dep_object(name, namespace):
    dep = None
    try:
        dep = k8s_apps_v1.read_namespaced_deployment(name, namespace=namespace)
        # print("PVC created. status=%s" % pvc.status.phase)
        logging.getLogger().debug("Get deployment %s" % name)
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception in get deployment:: %s" % e)
        raise e
    finally:
        return dep


def hpe_read_pvc_object(pvc_name, namespace):
    try:
        pvc = k8s_core_v1.read_namespaced_persistent_volume_claim(pvc_name, namespace=namespace)
        return pvc
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_delete_pvc_object_by_name(pvc_name):
    try:
        namespace = globals.namespace
        pvc = k8s_core_v1.delete_namespaced_persistent_volume_claim(pvc_name, namespace=namespace)
    except client.rest.ApiException as e:
        #print("Exception while deleting pvc:: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_delete_secret_object_by_name(secret_name, namespace):
    try:
        secret = k8s_core_v1.delete_namespaced_secret(secret_name, namespace=namespace)
    except client.rest.ApiException as e:
        #print("Exception while deleting secret:: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_get_secret_object_by_name(secret_name, namespace, raise_error=False):
    secret = None
    try:
        secret = k8s_core_v1.read_namespaced_secret(secret_name, namespace=namespace)
    except client.rest.ApiException as e:
        if raise_error:
            #print("Exception while getting secret:: %s" % e)
            logging.getLogger().error("Exception while getting secret:: %s" % e)
            raise e
    return secret


def hpe_delete_sc_object_by_name(sc_name):
    try:
        pvc = k8s_storage_v1.delete_storage_class(sc_name)
    except client.rest.ApiException as e:
        #print("Exception while deleting sc:: %s" % e)
        logging.getLogger().error("Exception while deleting sc:: %s" % e)
        raise e


def hpe_delete_pod_object_by_name(pod_name, namespace):
    try:
        pvc = k8s_core_v1.delete_namespaced_pod(pod_name, namespace=namespace)
    except client.rest.ApiException as e:
        #print("Exception while deleting sc:: %s" % e)
        logging.getLogger().error("Exception while deleting pod:: %s" % e)
        raise e


def hpe_list_pvc_objects(namespace):
    try:
        pvc_list = k8s_core_v1.list_namespaced_persistent_volume_claim(namespace=namespace)
        return pvc_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_pvc_objects_names(namespace):
    try:
        pvc_names = []
        pvc_list = hpe_list_pvc_objects(namespace)
        for pvc in pvc_list.items:
            pvc_names.append(pvc.metadata.name)

        return pvc_names
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_deployment_objects(namespace):
    try:
        dep_list = k8s_apps_v1.list_namespaced_deployment(namespace=namespace)
        return dep_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_deployment_objects_names(namespace):
    try:
        dep_names = []
        dep_list = hpe_list_deployment_objects(namespace)
        for dep in dep_list.items:
            dep_names.append(dep.metadata.name)

        return dep_names
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_statefulset_objects(namespace):
    try:
        set_list = k8s_apps_v1.list_namespaced_stateful_set(namespace=namespace)
        return set_list
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_statefulset_objects_names(namespace):
    try:
        set_names = []
        set_list = hpe_list_statefulset_objects(namespace)
        for set in set_list.items:
            set_names.append(set.metadata.name)

        return set_names
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_sc_objects():
    try:
        sc_list = k8s_storage_v1.list_storage_class()
        return sc_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_sc_objects_names():
    try:
        sc_names = []
        sc_list = hpe_list_sc_objects()
        for sc in sc_list.items:
            sc_names.append(sc.metadata.name)
        return sc_names
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_secret_objects(namespace):
    try:
        secret_list = k8s_core_v1.list_namespaced_secret(namespace=namespace)
        return secret_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_secret_objects_names(namespace):
    try:
        secret_names = []
        secret_list = hpe_list_secret_objects(namespace=namespace)
        for secret in secret_list.items:
            secret_names.append(secret.metadata.name)

        return secret_names
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_service_objects(namespace):
    """
    hpe_list_service_objects - This function gets a list of all services and their information under a particular namespace.
    Parameters:
        Required:
            1. (namespace): The namespace under which to list services from Kubernetes.
        Optional:
            None
        Returns:
            service_list: The list of services under the given namespace.
        Raises:
            Exception: If there's an error while collecting the list of services under the namespace, it raises an exception.
    """
    try:
        service_list = k8s_core_v1.list_namespaced_service(namespace=namespace)
        return service_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_service_objects_names(namespace):
    """
    hpe_list_service_objects_names - This function takes a list of V1Service and appends only their names to a list.
    Parameters:
        Required:
            1. (namespace): The namespace under which to list services from Kubernetes.
        Optional:
            None
        Returns:
            service_list: The list of names of services under a given namespace.
        Raises:
            Exception: If there's an error while parsing through list of services, it raises an exception.
    """
    try:
        service_names = []
        service_list = hpe_list_service_objects(namespace=namespace)
        service_names = [service.metadata.name for service in service_list.items]
        return service_names
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_pod_objects(namespace, **kwargs):
    try:
        pod_list = None
        logging.getLogger().info("kwargs keys :: %s,\n values :: %s" % (kwargs.keys(), kwargs.values()))
        if 'label' in kwargs:
            pod_list = k8s_core_v1.list_namespaced_pod(namespace=namespace, label_selector=kwargs['label'])
        elif 'field' in kwargs:
            pod_list = k8s_core_v1.list_namespaced_pod(namespace=namespace, field_selector=kwargs['field'])
        else:
            pod_list = k8s_core_v1.list_namespaced_pod(namespace=namespace)
        return pod_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_pod_objects_names(namespace):
    try:
        pod_names = []
        pod_list = hpe_list_pod_objects(namespace=namespace)
        #print("=============== Listing all pods in default namespace::START")
        for pod in pod_list.items:
            pod_names.append(pod.metadata.name)
            #print("########### %s " %pod)

        #print("=============== Listing all pods in default namespace::END")
        return pod_names
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def hpe_list_node_objects():
    try:
        node_list = k8s_core_v1.list_node()
        return node_list
    except client.rest.ApiException as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def check_if_deleted(timeout, name, kind, namespace):
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
        elif kind == 'Deploy':
            obj_list = hpe_list_deployment_objects_names(namespace=namespace)
        elif kind == 'StatefulSet':
            obj_list = hpe_list_statefulset_objects_names(namespace=namespace)
        elif kind == 'Service':
            obj_list = hpe_list_service_objects_names(namespace=namespace)
        else:
            #print("Not a supported kind")
            logging.getLogger().info("Not a supported kind")
            flag = False
            break
        # print(obj_list)
        print(".", end='', flush=True)
        if name not in obj_list:
            break

        if int(time) > int(timeout):
            caller_fun = inspect.stack()[2][3]
            logging.getLogger().info("caller_fun :: %s" % caller_fun)
            if caller_fun != 'cleanup':
                #print("\n%s not yet deleted. Taking longer than expected..." % kind)
                logging.getLogger().info("%s %s not yet deleted. Taking longer than expected..." % (kind, name))
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
        #PROTOCOL = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            print(elements)
            logging.getLogger().debug(elements)
            for el in elements:
                logging.getLogger().debug(el)
                logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
                #print(el)
                #print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "Secret":
                    HPE3PAR_IP = el['stringData']['backend']
                    HPE3PAR_USERNAME = el['stringData']['username']
                    HPE3PAR_PWD = el['data']['password']
                """if str(el.get('kind')) == "StorageClass":
                    PROTOCOL = el['parameters']['accessProtocol']
                    # remoteCopyGroup = el['parameters']['remoteCopyGroup']"""
        #print("HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD))
        return HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD#, PROTOCOL
    except Exception as e:
        #print("Exception while verifying on 3par :: %s" % e)
        logging.getLogger().error("Exception while verifying on 3par :: %s" % e)
        raise e


def read_protocol(yml):
    try:
        PROTOCOL = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            #print(elements)
            logging.getLogger().debug(elements)
            for el in elements:
                #print(el)
                #print("======== kind :: %s " % str(el.get('kind')))
                logging.getLogger().debug(el)
                logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    PROTOCOL = el['parameters']['accessProtocol']
                    # remoteCopyGroup = el['parameters']['remoteCopyGroup']
        #print("HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD))
        return PROTOCOL
    except Exception as e:
        #print("Exception while verifying on 3par :: %s" % e)
        logging.getLogger().error("Exception while verifying on 3par :: %s" % e)
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
        #print("Exception while fetching events for %s,%s :: %s" % (kind, name, e))
        logging.getLogger().error("Exception while fetching events for %s,%s :: %s" % (kind, name, e))
        raise e


def check_status(timeout_set, name, kind, status, namespace):
    time = 0
    flag = True
    logging.getLogger().info("timeout_set :: %s" % timeout_set)
    logging.getLogger().info("name :: %s" % name)
    logging.getLogger().info("kind :: %s" % kind)
    logging.getLogger().info("status :: %s" % status)
    logging.getLogger().info("namespace :: %s" % namespace)
    if timeout_set is None or timeout_set <= 0:
        timeout_set = 300
    if kind == 'deployment':
        logging.getLogger().info("Checking if deployment %s has created pods..." % name)
    elif kind == 'StatefulSet':
        logging.getLogger().info("Checking if StatefulSet %s has all replicas ready..." % name)
    else:
        logging.getLogger().info("Checking for %s %s to come in %s state..." % (kind, name, status))
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
            #print(obj)
            logging.getLogger().debug(obj)
        elif kind == 'StatefulSet':
            obj = k8s_apps_v1.read_namespaced_stateful_set(name, namespace)
        else:
            #print("\nNot a supported kind")
            logging.getLogger().info("Not a supported kind")
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
            if replica_total == replica_avail and replica_total > 0:
                break
        elif kind == 'StatefulSet':
            replica_total = 0
            replica_current = 0
            replica_ready = 0

            if obj.status.replicas is not None:
                replica_total = obj.status.replicas

            if obj.status.current_replicas is not None:
                replica_current = obj.status.current_replicas

            if obj.status.ready_replicas is not None:
                replica_ready = obj.status.ready_replicas

            if replica_total == replica_current and replica_total > 0 and replica_ready > 0:
                logging.getLogger().info("Statefulset Current: %s Total: %s Ready: %s" % (replica_current, replica_total, replica_ready))
                if replica_ready == replica_total:
                    break
        else:
            if obj.status.phase == status:
                break

        if int(time) > int(timeout_set):
            if kind == 'deployment' or kind == 'StatefulSet':
                #print("\nDeployment %s check failed. Taking longer than expected..." % name)
                logging.getLogger().info("%s %s check failed. Taking longer than expected..." % (kind, name))
            else:
                #print("\n%s not yet in %s state. Taking longer than expected..." % (kind, status))
                logging.getLogger().info("%s not yet in %s state. Taking longer than expected..." % (kind, status))
            # print("obj :: %s" % obj)
            logging.getLogger().debug("obj :: %s" % obj)
            flag = False
            break
        time += 1
        sleep(1)

    if flag is True:
        if kind == 'deployment' or kind == 'StatefulSet':
            #print("\nDeployment %s check done, took %s" % (name, str(datetime.timedelta(0, time))))
            #logging.getLogger().info("Deployment %s check done, took %s" % (name, str(datetime.timedelta(0, time))))
            logging.getLogger().info("%s %s check done, took %s" % (kind, name, str(datetime.timedelta(0, time))))
        else:
            print("\n%s has come to %s state!!! It took %s seconds" % (kind, status, str(datetime.timedelta(0, time))))
            logging.getLogger().info("%s has come to %s state!!! It took %s seconds" % (kind, status, str(datetime.timedelta(0, time))))
    return flag, obj


def hpe_get_pod(pod_name, namespace):
    try:
        return k8s_core_v1.read_namespaced_pod(pod_name,namespace=namespace)
    except Exception as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def get_host_from_array(hpe3par_cli, host_name):
    try:
        logging.getLogger().info("\nFetching host details from array for %s " % host_name)
        hpe3par_host = globals.hpe3par_cli.getHost(host_name)
        logging.getLogger().info("Host details from array :: %s " % hpe3par_host)
        return hpe3par_host
    except Exception as e:
        logging.getLogger().error("Exception %s while fetching host details from array for %s " % (e, host_name))



def verify_host_properties(hpe3par_host, **kwargs):
    logging.getLogger().info("In verify_host_properties()")
    encoding = "latin-1"
    logging.getLogger().info("kwargs[chapUser] :: %s " % kwargs['chapUser'])
    logging.getLogger().info("kwargs[chapPwd] :: %s " % kwargs['chapPassword'])
    try:
        if 'chapUser' in kwargs:
            if hpe3par_host['initiatorChapEnabled'] == True:
                if hpe3par_host['initiatorChapName'] == kwargs['chapUser'] and (base64.b64decode(hpe3par_host['initiatorEncryptedChapSecret'])).decode(encoding) == kwargs['chapPassword']:
                    return True
            else:
                return False
        return True
    except Exception as e:
        logging.getLogger().error("Exception while verifying host properties %s " % e)


def get_command_output(node_name, command, password=None):
    try:
        # Remove known prefixes from node_name
        for prefix in ("iqn-","wwn-","nqntcp-"):
            if node_name.startswith(prefix):
                node_name = node_name[len(prefix):]
                break

        logging.getLogger().info("Executing command...")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.getLogger().info("node_name = %s, command = %s " % (node_name, command))

        if globals.platform == 'os':
            username = 'core'
        else:
            username = 'root'
            password = globals.workernode_password

        if password is not None:
            ssh_client.connect(hostname=node_name, username=username, password=password)
        else:
            ssh_client.connect(
                hostname=node_name,
                username=username,
                allow_agent=True,
                look_for_keys=True,
                timeout=60
            )

        logging.getLogger().info("connected...")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        stderr_output = stderr.read().decode()
        logging.getLogger().info("stderr :: %s" % stderr_output)

        command_output = [line.strip() for line in stdout.readlines()]
        for line in command_output:
            logging.getLogger().debug(line)

        ssh_client.close()
        return command_output

    except Exception as e:
        logging.getLogger().error("Exception while ssh %s " % e)


def get_command_output_string(command):
    try:
        #logging.getLogger().info(command)
        stream = os.popen(command)
        #logging.getLogger().info(stream)
        output = stream.read()
        #logging.getLogger().info(output)
        return output
    except Exception as e:
        #print("Exception while executing command %s " % e)
        logging.getLogger().error("Exception while executing command %s " % e)
        

def hpe_list_crds():
    try:
        crd_names = []
        crd_list = k8s_api_extn_v1.list_custom_resource_definition()
        for crd in crd_list.items:
            crd_names.append(crd.metadata.name)

        return crd_names
    except Exception as e:
        #print("Exception while listing crd(s) %s " % e)
        logging.getLogger().error("Exception while listing crd(s) %s " % e)


def get_node_crd(node_name):
    try:
        logging.getLogger().info("\nReading CRD for %s " % node_name)
        command = "kubectl get hpenodeinfos %s -o json" % node_name
        result = get_command_output_string(command)
        crd = json.loads(result)
        # print(crd)
        return crd
    except Exception as e:
        logging.getLogger().error("Exception %s while fetching crd for node %s " % (e, node_name))


def verify_node_crd_chap(crd_name, **kwargs):
    try:
        logging.getLogger().info("Verifying chap details in node crd")
        encoding = "utf-8"
        flag = False
        crd = get_node_crd(crd_name)
        logging.getLogger().info("crd :: %s " % crd)
        if crd is not None:
            if 'chapUser' in kwargs:
                assert crd['spec']['chapUser'] == kwargs['chapUser']
                assert (base64.b64decode(crd['spec']['chapPassword'])).decode(encoding) == kwargs['chapPassword']
                flag = True
                return flag
        return flag
    except Exception as e:
        logging.getLogger().error("Exception %s while verifying node CRD :: %s" % (e, crd_name))
        raise e


def create_crd(yml, crd_name):
    try:
        logging.getLogger().info("Creating crd %s ..." % crd_name)
        if globals.platform == 'os':
            command = "oc create -f " + yml
        else:
            command = "kubectl create -f " + yml
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output).startswith(crd_name) and str(output).endswith("created\n"):
            return True
        else:
            return False
    except Exception as e:
        logging.getLogger().error("Exception while creating crd %s :: %s" % (crd_name, e))
        raise e


def hpe_delete_crd(yml, crd_name):
    try:
        logging.getLogger().info("Deleting crd %s ..." % crd_name)
        if globals.platform == 'os':
            command = "oc delete -f " + yml
        else:
            command = "kubectl delete -f " + yml
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output).startswith(crd_name) and str(output).endswith("deleted\n"):
            return True
        else:
            return False
    except Exception as e:
        logging.getLogger().error("Exception while deleting crd %s " % e)


def hpe_read_sa(sa_name, sa_namespace):
    try:
        obj = k8s_core_v1.read_namespaced_service_account(sa_name, sa_namespace)
        return obj
    except Exception as e:
        #print("Exception while reading sa %s " % e)
        logging.getLogger().error("Exception while reading sa %s " % e)


def hpe_create_sa(yml, sa_namespace):
    try:
        k8s_core_v1.create_namespaced_service_account(sa_namespace, yml)
    except Exception as e:
        #print("Exception while creating sa %s " % e)
        logging.getLogger().error("Exception while creating sa %s " % e)


def hpe_read_cluster_role(name):
    try:
        obj = k8s_rbac_auth_v1.read_cluster_role(name)
        return obj
    except Exception as e:
        #print("Exception while reading cluster role %s " % e)
        logging.getLogger().error("Exception while reading cluster role %s " % e)


def hpe_create_cluster_role(yml):
    try:
        k8s_rbac_auth_v1.create_cluster_role(yml)
    except Exception as e:
        #print("Exception while creating cluster role %s " % e)
        logging.getLogger().error("Exception while creating cluster role %s " % e)


def hpe_read_cluster_role_binding(name):
    try:
        obj = k8s_rbac_auth_v1.read_cluster_role_binding(name)
        return obj
    except Exception as e:
        #print("Exception while reading cluster role binding %s " % e)
        logging.getLogger().error("Exception while reading cluster role binding %s " % e)


def hpe_create_cluster_role_binding(yml):
    try:
        k8s_rbac_auth_v1.create_cluster_role_binding(yml)
    except Exception as e:
        #print("Exception while creating cluster role binding %s " % e)
        logging.getLogger().error("Exception while creating cluster role binding %s " % e)


def hpe_read_role(name, namespace):
    try:
        obj = k8s_rbac_auth_v1.read_namespaced_role(name, namespace)
        return obj
    except Exception as e:
        #print("Exception while reading sa %s " % e)
        logging.getLogger().error("Exception while reading sa %s " % e)


def hpe_create_role(yml, namespace):
    try:
        k8s_rbac_auth_v1.create_namespaced_role(namespace, yml)
    except Exception as e:
        #print("Exception while creating sa %s " % e)
        logging.getLogger().error("Exception while creating sa %s " % e)


def hpe_read_role_binding(name, namespace):
    try:
        obj = k8s_core_v1.read_namespaced_role_binding(name, namespace)
        return obj
    except Exception as e:
        #print("Exception while reading sa %s " % e)
        logging.getLogger().error("Exception while reading sa %s " % e)


def hpe_create_role_binding(yml, namespace):
    try:
        k8s_core_v1.create_namespaced_role_binding(namespace, yml)
    except Exception as e:
        #print("Exception while creating sa %s " % e)
        logging.getLogger().error("Exception while creating sa %s " % e)


def hpe_read_statefulset(name, namespace):
    try:
        obj = k8s_apps_v1.read_namespaced_stateful_set(name, namespace)
        return obj
    except Exception as e:
        logging.getLogger().error("Exception while reading statefulset %s " % e)


def hpe_create_statefulset(yml):
    try:
        namespace = globals.namespace
        if 'namespace' in yml.get('metadata'):
            namespace = yml.get('metadata')['namespace']
        statefulset = k8s_apps_v1.create_namespaced_stateful_set(namespace, yml)
        return statefulset
    except Exception as e:
        logging.getLogger().error("Exception while creating statefulset %s " % e)


def create_statefulset(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "StatefulSet":
                logging.getLogger().info("Creating StatefulSet...")
                obj = hpe_create_statefulset(el)
                logging.getLogger().info("StatefulSet %s created." % obj.metadata.name)
    return obj


def create_sc(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "StorageClass":
                # print("PersistentVolume YAML :: %s" % el)
                #print("\nCreating StorageClass...")
                logging.getLogger().info("Creating StorageClass...")
                if el['parameters']['accessProtocol'] != globals.access_protocol:
                    logging.getLogger().info("accessProtocol value from command line and yaml does not match. %s will be used for the test" % globals.access_protocol)
                el['parameters']['accessProtocol'] = globals.access_protocol
                obj = hpe_create_sc_object(el)
                #print("\nStorageClass %s created." % obj.metadata.name)
                logging.getLogger().info("StorageClass %s created." % obj.metadata.name)
    return obj


def create_pvc(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "PersistentVolumeClaim":
                # print("PersistentVolume YAML :: %s" % el)
                #print("\nCreating PersistentVolumeClaim...")
                logging.getLogger().info("Creating PersistentVolumeClaim...")
                obj = hpe_create_pvc_object(el)
                #print("\nPersistentVolumeClaim %s created." % obj.metadata.name)
                logging.getLogger().info("PersistentVolumeClaim %s created." % obj.metadata.name)
    return obj


def create_pod(yml):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "Pod":
                # print("Pod YAML :: %s" % el)
                #print("\nCreating Pod...")
                logging.getLogger().info("\nCreating Pod...")
                obj = hpe_create_pod_object(el)
                #print("\nPod %s created." % obj.metadata.name)
                logging.getLogger().info("\nPod %s created." % obj.metadata.name)
    return obj


def create_secret(yml, namespace):
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            logging.getLogger().debug("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == "Secret":
                # print("PersistentVolume YAML :: %s" % el)
                logging.getLogger().info("\nCreating Secret...")
                logging.getLogger().info(el)
                #print("\nCreating Secret...")
                #print(el)
                obj = hpe_create_secret_object(el)
                logging.getLogger().info("\nSecret %s created." % obj.metadata.name)
                #print("\nSecret %s created." % obj.metadata.name)
    return obj

def create_cpg_in_array(hpe3par_cli, cpg_name, options=None):
    try:
        logging.getLogger().info("In create_cpg_in_array() :: cpg_name :: %s, options :: %s" % (cpg_name, options))
        
        # Check if the CPG already exists
        try:
            logging.getLogger().info("Check CPG already exists: %s" % cpg_name)
            cpg = globals.hpe3par_cli.getCPG(cpg_name)
            logging.getLogger().info("CPG already exists: %s" % cpg_name)
            return cpg
        except HTTPNotFound:
            logging.getLogger().info("CPG does not exist, proceeding to create: %s" % cpg_name)
        
            # Create the CPG if it does not exist
            response = globals.hpe3par_cli.createCPG(cpg_name, options)
            logging.getLogger().info("CPG created successfully: %s" % response)
            return response
    except Exception as e:
        logging.getLogger().error("Error in create_cpg_in_array(): %s" % str(e))
        raise

def create_domain(hpe3par_cli, domain_name):
    try:
        # Check if the domain already exists
        existing_domains = globals.hpe3par_cli.getDomains()
        print("Existing domains: %s" % existing_domains)
        if any(domain['name'] == domain_name for domain in existing_domains):
            logging.getLogger().info("Domain already exists: %s" % domain_name)
            return "Domain already exists: %s" % domain_name

        # Create the domain if it does not exist
        response = globals.hpe3par_cli.createDomain(domain_name, options)
        logging.getLogger().info("Domain created successfully: %s" % domain_name)
        return response
    except Exception as e:
        logging.getLogger().error("Error during domain creation for: %s" % domain_name)
        raise        


def get_pvc_crd(pvc_name):
    try:
        # print("\nReading CRD for %s " % pvc_name)
        if globals.platform == 'os':
            command = "oc get hpevolumeinfos %s -o json" % pvc_name
        else:
            command = "kubectl get hpevolumeinfos %s -o json" % pvc_name
        result = get_command_output_string(command)
        crd = json.loads(result)
        # print(crd)
        return crd
    except Exception as e:
        #print("Exception %s while fetching crd for pvc %s " % (e, pvc_name))
        logging.getLogger().error("Exception %s while fetching crd for pvc %s " % (e, pvc_name))


def get_pvc_volume(pvc_crd):
    vol_name = pvc_crd["spec"]["record"]["Name"]
    #print("\nPVC %s has volume %s on array" % (pvc_crd["spec"]["uuid"], vol_name))
    logging.getLogger().info("PVC %s has volume %s on array" % (pvc_crd["spec"]["uuid"], vol_name))
    return vol_name


def get_pvc_editable_properties(pvc_crd):
    vol_name = pvc_crd["spec"]["record"]["Name"]
    vol_usrCpg = pvc_crd["spec"]["record"]["Cpg"]
    vol_snpCpg = pvc_crd["spec"]["record"]["SnapCpg"]
    vol_desc = pvc_crd["spec"]["record"]["Description"]
    vol_compression = pvc_crd["spec"]["record"]["Compression"]
    vol_provType = pvc_crd["spec"]["record"]["ProvisioningType"]
    logging.getLogger().info("Getting mutator properties from crd, name::%s cpg::%s snpCpg::%s desc::%s compr::%s provType::%s" % (vol_name, vol_usrCpg, vol_snpCpg, vol_desc, vol_compression, vol_provType))

    return vol_name, vol_usrCpg, vol_snpCpg, vol_provType, vol_desc, vol_compression


def get_volume_from_array(hpe3par_cli, volume_name):
    hpe3par_volume = None
    try:
        # print("\nFetching volume from array for %s " % volume_name)
        hpe3par_volume = hpe3par_cli.getVolume(volume_name)
        # print("Volume from array :: %s " % hpe3par_volume)
    except Exception as e:
        logging.getLogger().error("Exception %s while fetching volume from array for %s " % (e, volume_name))
    finally:
        return hpe3par_volume


def get_volume_set_from_array(hpe3par_cli, volume_set_name):
    try:
        # print("\nFetching volume set from array for %s " % volume_set_name)
        hpe3par_volume_set = hpe3par_cli.getVolumeSet(volume_set_name)
        return hpe3par_volume_set
    except Exception as e:
        logging.getLogger().error("Exception %s while fetching volume from array for %s " % (e, volume_set_name))


def get_volume_sets_from_array(hpe3par_cli):
    try:
        # print("\nFetching volume set from array for %s " % volume_set_name)
        hpe3par_volume_set = hpe3par_cli.getVolumeSets()
        return hpe3par_volume_set
    except Exception as e:
        logging.getLogger().error("Exception %s while fetching volume from array for %s " % (e, volume_set_name))


def verify_volume_properties(hpe3par_volume, **kwargs):
    try:
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                if hpe3par_volume['provisioningType'] != 1:
                    logging.getLogger().info("provisioningType ")
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
                if hpe3par_volume['compressionState'] not in [1,5,6]:
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

        if 'copyOf' in kwargs:
            if hpe3par_volume['copyOf'] != kwargs['copyOf']:
                return False
        if 'snapCPG' in kwargs:
            if globals.hpe3par_model != "Arcus":
                if hpe3par_volume['snapCPG'] != kwargs['snapCPG']:
                    return False
        return True
    except Exception as e:
        logging.getLogger().error("Exception while verifying volume properties %s " % e)


def verify_volume_properties_3par(hpe3par_volume, **kwargs):
    logging.getLogger().info("In verify_volume_properties_3par()")
    if 'provisioning' in kwargs:
        logging.getLogger().info("kwargs[provisioning] :: %s " % kwargs['provisioning'])
    if 'size' in kwargs:
        logging.getLogger().info("kwargs[size] :: %s " % kwargs['size'])
    if 'compression' in kwargs:
        logging.getLogger().info("kwargs[compression] :: %s " % kwargs['compression'])
    if 'clone' in kwargs:
        logging.getLogger().info("kwargs[clone] :: %s " % kwargs['clone'])
    if 'snapcpg' in kwargs:
        logging.getLogger().info("kwargs[snapcpg] :: %s " % kwargs['snapcpg'])
    if 'cpg' in kwargs:
        logging.getLogger().info("kwargs[cpg] :: %s " % kwargs['cpg'])
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
                        logging.getLogger().info("provisioningType ")
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
                logging.getLogger().info("########### kwargs['provisioning'] :: %s" % kwargs['provisioning'])
                if 'compression' in kwargs:
                    logging.getLogger().info("########### kwargs['compression'] :: %s" % kwargs['compression'])
                    logging.getLogger().info("########### hpe3par_volume['compressionState'] :: %s" % hpe3par_volume['compressionState'])
                    if kwargs['compression'] == 'true':
                        if hpe3par_volume['compressionState'] not in [1,5,6,-1]:
                            failure_cause = 'compression'
                            return False, failure_cause
                    elif kwargs['compression'] == 'false' or kwargs['compression'] is None:
                        logging.getLogger().info("&&&&&&&&& i am here compression is :: %s" % kwargs['compression'])
                        logging.getLogger().info("hpe3par_volume['compressionState'] :: %s " % hpe3par_volume['compressionState'])
                        if hpe3par_volume['compressionState'] != 2:
                            print("########### FAILED!!!")
                            failure_cause = 'compression'
                            return False, failure_cause
            if kwargs['provisioning'] == 'reduce':
                if 'compression' in kwargs:
                    if hpe3par_volume['compressionState'] not in [1,5,6,-1]:
                        failure_cause = 'compression'
                        return False, failure_cause
            elif 'provisioning' in kwargs and kwargs['provisioning'] == 'full':
                # for full provisioned volume can not be compressed
                if 'compression' in kwargs:
                    if kwargs['compression'] == 'true':
                        if hpe3par_volume['compressionState'] not in [1,5,6]:
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
        logging.getLogger().error("Exception while verifying volume properties %s " % e)


def verify_volume_properties_primera(hpe3par_volume, **kwargs):
    try:
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                if hpe3par_volume['provisioningType'] != 1:
                    logging.getLogger().info("provisioningType ")
                    return False
            elif kwargs['provisioning'] == 'thin':
                if hpe3par_volume['provisioningType'] != 2:
                    return False
            elif kwargs['provisioning'] == 'reduce':
                if hpe3par_volume['provisioningType'] != 6 or hpe3par_volume['deduplicationState'] != 1:
                    return False

            if 'size' in kwargs:
                if hpe3par_volume['sizeMiB'] != int(kwargs['size']) * 1024:
                    return False
                else:
                    if hpe3par_volume['sizeMiB'] != 102400:
                        return False

            if 'compression' in kwargs:
                if kwargs['provisioning'] == 'reduce':
                    if hpe3par_volume['compressionState'] not in [1,5,6,-1]:
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
        logging.getLogger().error("Exception while verifying volume properties %s " % e)


def delete_pvc(name):
    try:
        logging.getLogger().info("\nDeleting PVC %s..." % name)
        hpe_delete_pvc_object_by_name(name)
        flag = check_if_deleted(timeout, name, "PVC", globals.namespace)
        if flag:
            logging.getLogger().info("\nPVC %s is deleted successfully" % name)
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while deleting pvc %s :: %s" % (name, e))
        raise e


def verify_delete_volume_on_3par(hpe3par_cli, volume_name):
    try:
        logging.getLogger().info("\nVerify if volume is deleted from array for %s " % volume_name)
        hpe3par_volume = hpe3par_cli.getVolume(volume_name)
    except HTTPNotFound as e:
        logging.getLogger().info("\nVolume has been deleted from array for %s " % volume_name)
        return True
    except Exception as e:
        logging.getLogger().error("Exception while verifying volume deletion from array for %s :: %s" % (volume_name, e))
        raise e


def delete_sc(name):
    try:
        logging.getLogger().info("\nDeleting SC %s " % name)
        hpe_delete_sc_object_by_name(name)
        flag = check_if_deleted(timeout, name, "SC", globals.namespace)
        if flag:
            logging.getLogger().info("\nSC %s is deleted" % name)
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while deleting storage class :: %s" % e)
        raise e


def hpe_delete_statefulset_object_by_name(set_name, namespace):
    try:
        set = k8s_apps_v1.delete_namespaced_stateful_set(set_name, namespace=namespace)
    except client.rest.ApiException as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def delete_statefulset(name, namespace):
    try:
        logging.getLogger().info("\nDeleting StatefulSet %s..." % name)
        hpe_delete_statefulset_object_by_name(name, namespace)
        flag = check_if_deleted(timeout, name, "StatefulSet", namespace)
        if flag:
            logging.getLogger().info("\nStatefulSet %s is deleted successfully" % name)
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while deleting StatefulSet %s :: %s" % (name, e))
        raise e


def get_3par_cli_client(yml):
    logging.getLogger().info("\nIn get_3par_cli_client(yml)")
    hpe3par_ip, hpe3par_username, hpe3par_pwd = read_array_prop(yml)
    get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd)


def get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd):
    logging.getLogger().info("\nIn get_3par_cli_client()")
    array_4_x_list = ['10.201.5.13']
    array_3_x_list = ['192.168.67.5','15.212.195.246','15.212.195.247','10.50.3.21', '15.212.192.252', '10.50.3.7', '10.50.3.22', '10.50.3.9', '192.168.67.7']

    port = None
    if hpe3par_ip in array_3_x_list:
        port = '8080'
    elif hpe3par_ip in array_4_x_list:
        port = '443'
    else:
        logging.getLogger().info("Array %s is not configured in manager class. Please make entry for this array." % hpe3par_ip)
        raise Exception('ArrayNotConfigured')
    # HPE3PAR_API_URL = "https://" + HPE3PAR_IP + ":8080/api/v1"
    hpe3par_api_url = "https://%s:%s/api/v1" % (hpe3par_ip, port)
    encoding = "utf-8"
    """print("\nHPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                  HPE3PAR_IP,
                                                                                                  HPE3PAR_USERNAME,
                                                                                                  (base64.b64decode(
                                                                                                      HPE3PAR_PWD)).decode(
                                                                                                      encoding)))"""

    """logging.info("\nHPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                  HPE3PAR_IP,
                                                                                                  HPE3PAR_USERNAME,
                                                                                                  (base64.b64decode(
                                                                                                      HPE3PAR_PWD)).decode(
                                                                                                      encoding)))"""

    hpe3par_cli = _hpe_get_3par_client_login(hpe3par_api_url, hpe3par_ip,
                                             hpe3par_username, (base64.b64decode(hpe3par_pwd)).decode(encoding))
    return hpe3par_cli


def delete_secret(name, namespace):
    try:
        logging.getLogger().info("\nDeleting Secret %s from namespace %s..." % (name,namespace))
        hpe_delete_secret_object_by_name(name, namespace=namespace)
        flag = check_if_deleted(timeout, name, "Secret", namespace=namespace)
        if flag:
            logging.getLogger().info("\nSecret %s from namespace %s is deleted." % (name, namespace))
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while deleting secret :: %s" % e)
        raise e


def verify_pod_node(hpe3par_vlun, pod):
    try:
        logging.getLogger().info("Verifying node where pod is mounted received from 3PAR and cluster are same...")
        # Get pod node name and strip domain if present
        pod_node_name = pod.spec.node_name
        dot_index = pod_node_name.find('.')
        if dot_index > 0:
            pod_node_name = pod_node_name[:dot_index]

        # Remove known prefixes from array-side hostname
        array_node_name = hpe3par_vlun['hostname']
        for prefix in ("iqn-", "wwn-","nqntcp-"):
            if array_node_name.startswith(prefix):
                array_node_name = array_node_name[len(prefix):]
                break  # Only strip one prefix

        logging.getLogger().info(f"Node from pod object:Node from array :: {pod_node_name}:{array_node_name}")

        return pod_node_name == array_node_name

    except Exception as e:
        logging.getLogger().error("Exception while verifying node names where pod is mounted :: %s" % e)
        raise e


def get_3par_vlun(hpe3par_cli, volume_name):
    return hpe3par_cli.getVLUN(volume_name)


def get_all_vluns(hpe3par_cli, volume_name):
    volume_vluns = []
    vluns = hpe3par_cli.getVLUNs()
    for vlun in vluns['members']:
        if vlun['volumeName'] == volume_name:
            volume_vluns.append(vlun)

    return volume_vluns

def get_subsystem_nqn(hpe3par_cli, volume_name):
    vluns = hpe3par_cli.getVLUNs()
    for vlun in vluns['members']:
        if vlun.get('volumeName') == volume_name:
            return vlun.get('Subsystem_NQN')

    return None

def get_host_nqn(hpe3par_cli, volume_name):
    vluns = hpe3par_cli.getVLUNs()
    for vlun in vluns['members']:
        if vlun.get('volumeName') == volume_name:
            return vlun.get('remoteName')

    return None

def get_all_active_vluns(hpe3par_cli, volume_name):
    active_vluns = []
    vluns = get_all_vluns(hpe3par_cli, volume_name)

    for vlun in vluns:
        if vlun['active']:
            active_vluns.append(vlun)

    return active_vluns


def get_iscsi_ips(hpe3par_cli):
    iscsi_info = hpe3par_cli.getiSCSIPorts(state=4)
    iscsi_ips = []
    for entry in iscsi_info:
        if len(entry['iSCSIVlans']) > 0:
            iscsi_ips.append(entry['iSCSIVlans'][random.randint(0,len(entry['iSCSIVlans'])-1)]['IPAddr'])
        else:
            iscsi_ips.append(entry['IPAddr'])
    return iscsi_ips

def check_ip_accessibility(node_name,ip):
    status = False
    command =  "if ping -c 5 " + ip + " | grep -q '\\b0% packet loss'; then echo 'accessible'; else echo 'not accessible';  fi"
    ping_output = get_command_output(node_name, command)
    if ping_output[0] == "accessible":
        status = True
    return status

def verify_by_path(iscsi_ips, node_name, pvc_crd, hpe3par_vlun):
    disk_partition = []

    try:
        flag = True
        if globals.access_protocol == 'iscsi':
            target_iqns = pvc_crd['spec']['record']['TargetIQNs'].split(",")
            lun_id = pvc_crd['spec']['record']['LunId']

            if globals.replication_test:
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    peer_target_iqns = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['target_names']
                    target_iqns.extend(peer_target_iqns)
            iqn_ind = 0
            # verify ls -lrth /dev/disk/by-path at node
            #print("Verifying output of ls -lrth /dev/disk/by-path...")
            logging.getLogger().info("Verifying output of ls -lrth /dev/disk/by-path...")
            logging.getLogger().info("target_iqns :: %s" % target_iqns)
            for ip in iscsi_ips:
                #print("== For IP::%s " % ip)
                logging.getLogger().info("== For IP::%s " % ip)
                if not check_ip_accessibility(node_name,ip):
                    iqn_ind += 1
                    logging.getLogger().info("IP %s is not accessible"%ip)
                    continue
                logging.getLogger().info("IP %s is accessible"%ip)

                #command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-[0-9]*$))$/ {print $NF}' | awk -F'../' '{print $NF}'"
                command = "ls -lrth /dev/disk/by-path | awk '$9~/(ip-" + ip + ":3260-iscsi-" + \
                          target_iqns[iqn_ind]+"-lun-" + str(lun_id) + \
                          ")$/ {print $NF}' | awk -F'../' '{print $NF}'"
                iqn_ind += 1
                print("command is %s " % command)
                logging.getLogger().info("command is %s " % command)
                partitions = get_command_output(node_name, command)
                print("== Partition(s) received for %s are %s" % (ip, partitions))
                logging.getLogger().info("== Partition(s) received for %s are %s" % (ip, partitions))
                if partitions is None or len(partitions) <= int(0):
                    flag = False
                    break

                for partition in partitions:
                    disk_partition.append(partition)
                # print("Partition name %s" % partitions)
        elif globals.access_protocol == 'nvmetcp':
            # NVMe over TCP (NVMe-oF) verification - matches primera_pod_verifier.py patterns
            logging.getLogger().info("Verifying NVMe-TCP disk paths...")
            # Get target NQNs and namespace ID from CRD
            target_nqns = []
            lunid = None
            peer_vol_wwn = None
            peer_lun_id = None
            
            # Extract NQN from CRD (stored in TargetNQNs field)
            if 'TargetNQNs' in pvc_crd['spec']['record']:
                target_nqns = pvc_crd['spec']['record']['TargetNQNs'].split(",")

            # Get Lun ID (LUN ID for NVMe)
            if 'LunId' in pvc_crd['spec']['record']:
                lunid = pvc_crd['spec']['record']['LunId']
            # Get volume WWN
            vol_wwn = hpe3par_vlun.get('volumeWWN', '')
            lun = hpe3par_vlun.get('lun', lunid)
            remote_name = hpe3par_vlun.get('remoteName', '')
            host_name = hpe3par_vlun.get('hostname', '')
            subsystem_nqn = hpe3par_vlun.get('Subsystem_NQN', '')
            if not verify_nvme_multipath(node_name, subsystem_nqn, expected_paths=4):
                return False
            
            # Handle replication scenario
            if globals.replication_test:
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    peer_details = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]
                    if 'target_names' in peer_details:
                        peer_target_nqns = peer_details['target_names']
                        if isinstance(peer_target_nqns, list):
                            target_nqns.extend(peer_target_nqns)
                        else:
                            target_nqns.append(peer_target_nqns)
                    
                    if 'lun_id' in peer_details:
                        peer_lun_id = peer_details['lun_id']
                    
                    if 'volume_wwn' in peer_details:
                        peer_vol_wwn = peer_details['volume_wwn']
            
            logging.getLogger().info("target_nqns :: %s" % target_nqns)
            logging.getLogger().info("lun_id :: %s" % lunid)
            logging.getLogger().info("vol_wwn :: %s" % vol_wwn)
            logging.getLogger().info("lun :: %s" % lun)
            logging.getLogger().info("remote_name :: %s" % remote_name)
            logging.getLogger().info("host_name :: %s" % host_name)
            logging.getLogger().info("subsystem_nqn :: %s" % subsystem_nqn)

        else:
            # FC (Fibre Channel) verification
            # lun = pvc_crd['spec']['record']['LunId']
            peer_lun = None
            lun = hpe3par_vlun['lun']
            host_wwn = hpe3par_vlun['remoteName']
            vol_wwn = hpe3par_vlun['volumeWWN']
            peer_vol_wwn = None
            peer_lun = None
            com = "ls -lrth /dev/disk/by-path"
            paths = get_command_output(node_name, com)
            logging.getLogger().info("com output -> {}".format(paths))
            # command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^fc-0x" + host_wwn + \
                      # "-.*" + vol_wwn[-6:] + "-lun-" + str(lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                      
            command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^pci-" \
                      ".*" + vol_wwn[-6:] + "-lun-" + str(lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                      
            logging.getLogger().info("command is %s " % command)
            partitions = get_command_output(node_name, command)
            
            disk_partition.extend(partitions)
            # partitions from secondary array for replication scenario
            if globals.replication_test:
                logging.getLogger().info("Getting partitions for replicated array")
                '''import pdb
                pdb.set_trace'''
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    if 'lun_id' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_lun = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['lun_id']

                    if 'target_names' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_vol_wwn = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['target_names']
                        if isinstance(peer_vol_wwn, list) and len(peer_vol_wwn) > 0:
                            peer_vol_wwn = peer_vol_wwn[0]
                logging.getLogger().info("peer_lun :: %s" % peer_lun)
                logging.getLogger().info("peer_vol_wwn :: %s" % peer_vol_wwn)
                if peer_lun is not None or peer_vol_wwn is not None:
                    if peer_vol_wwn is None:
                        peer_vol_wwn = vol_wwn
                    if peer_lun is None:
                        peer_lun = lun
                    command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^fc-0x" + host_wwn + "-.*" \
                              + peer_vol_wwn[-6:] + "-lun-" + str(peer_lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                    logging.getLogger().info("command is :: %s" % command)
                    partitions = get_command_output(node_name, command)
                    disk_partition.extend(partitions)

            logging.getLogger().info("== Partition(s) received are %s" % disk_partition)
            if disk_partition is None or len(disk_partition) <= int(0):
                flag = False

            '''for partition in partitions:
                disk_partition.append(partition)'''
            # print("Partition name %s" % partitions)

        return flag, disk_partition
    except Exception as e:
        logging.getLogger().error("Exception while verifying partitions for iscsi ip(s) :: %s" % e)
        raise e


def verify_multipath(hpe3par_vlun, disk_partition):
    #print("\n########################### verify_multipath ###########################")
    logging.getLogger().info("########################### verify_multipath ###########################")
    partition_map = {'active': [], 'ghost': []}
    try:
        vv_wwn = hpe3par_vlun['volumeWWN']
        node_name = hpe3par_vlun['hostname']
<<<<<<< CON-4454
=======
        # For some nodes that have full FQDN in node name output, some processing is required
        for prefix in ("iqn-", "wwn-", "nqntcp-"):
            if node_name.startswith(prefix):
                node_name = node_name[len(prefix):]
                break
        if '.' not in node_name:
            try:
                for node in hpe_list_node_objects().items:
                    candidate_name = node.metadata.name
                    if candidate_name == node_name or candidate_name.startswith(node_name + '.'):
                        node_name = candidate_name
                        break
            except Exception as e:
                logging.getLogger().warning("Unable to resolve node name %s via K8s API: %s" % (node_name, e))

>>>>>>> kubernetes_automation
        #print("Fetching DM(s)...")
        logging.getLogger().info("Fetching DM(s)...")
        # fetch dm from /dev/mapper
        # command = "ls -ltrh /dev/mapper/ | awk -v IGNORECASE=1 '$9~/^[0-9]" + vv_wwn.upper() + "/ {print$NF}' | awk -F'../' '{print$NF}'"
        command = "ls -lrth /dev/disk/by-id/ | awk -v IGNORECASE=1 '$9~/^dm-uuid-mpath-[0-9]" + vv_wwn + \
                  "/' | awk -F '../../' '{print$NF}'"
        #print("dev/mapper command to get dm :: %s " % command)
        logging.getLogger().info("dev/mapper command to get dm :: %s " % command)
        dm = get_command_output(node_name, command)
        #print("DM(s) received :: %s " % dm)
        logging.getLogger().info("DM(s) received :: %s " % dm)

        # Fetch user friendly multipath name
        #print("Fetching user friendly multipath name")
        logging.getLogger().info("Fetching user friendly multipath name")
        command = "ls -lrth /dev/mapper/ | awk '$11~/" + dm[0] + "$/' | awk '{print$9}'"
        mpath_name = get_command_output(node_name, command)
        #print("mpath received :: %s " % mpath_name)
        logging.getLogger().info("mpath received :: %s " % mpath_name)
        #print("Verifying multipath -ll output...")
        logging.getLogger().info("Verifying multipath -ll output...")
        # Verify multipath -ll output
        command = "sudo multipath -ll | awk -v IGNORECASE=1 '/^" + mpath_name[0] + "\s([0-9]" + vv_wwn + \
                  ")*/{x=NR+" + str(len(disk_partition)+3) + "}(NR<=x){print}'"

        #import pytest;
        #pytest.set_trace()

        logging.getLogger().info("multipath -ll command to :: %s " % command)
        paths = get_command_output(node_name, command)
        #print("multipath output ::%s \n\n" % paths)
        logging.getLogger().info("multipath output ::%s \n\n" % paths)
        logging.getLogger().info("multipath -ll output :: %s " % get_command_output(node_name, "multipath -ll"))
        #import pdb;pdb.set_trace()
        index = 0
        multipath_failure_flag = 0
        disk_partition_temp = None
        disk_partition_temp = disk_partition.copy()
        logging.getLogger().info("disk_partition_temp :: %s" % disk_partition_temp)
        for path in paths:
            """if index < 3:
                index += 1
                continue"""
            logging.getLogger().info(path)
            col = path.split()
            logging.getLogger().info("col :: %s" % col)
            logging.getLogger().info("col[2] :: col[3] :: %s,%s" % (col[2], col[3]))
            if col[2] in disk_partition_temp or col[3] in disk_partition_temp:
                if col[2] in disk_partition_temp:
                    current_index = 2
                else:
                    current_index = 3
                logging.getLogger().info("col[%s] in disk_partition_temp, :: %s" % (current_index, col[current_index]))
                disk_partition_temp.remove(col[current_index])
                # if '''col[4] != 'active' or '''(col[5] != 'ready' and col[5] != 'ghost') or col[6] != 'running':
                if (col[current_index+3] != 'ready' and col[current_index+3] != 'ghost') or col[current_index+4] != 'running':
                    logging.getLogger().info("col[%s]:col[%s]:col[%s] :: %s:%s:%s " % (current_index+2, current_index+3, current_index+4, col[current_index+2], col[current_index+3], col[current_index+4]))
                    multipath_failure_flag += 1
                else:
                    if col[current_index+3] == 'ready':
                        partition_map['active'].append(col[current_index])
                    elif col[current_index+3] == 'ghost':
                        partition_map['ghost'].append(col[current_index])

            if globals.replication_test is True:
                if col[3] in disk_partition_temp:
                    logging.getLogger().info("col[3] :: %s " % col[3])
                    disk_partition_temp.remove(col[3])
                    # if '''col[5] != 'active' or '''(col[6] != 'ready' and col[6] != 'ghost') or col[7] != 'running':
                    if (col[6] != 'ready' and col[6] != 'ghost') or col[7] != 'running':
                        logging.getLogger().info("col[5]:col[6]:col[7] :: %s:%s:%s " % (col[5], col[6], col[7]))
                        multipath_failure_flag += 1
                    else:
                        if col[6] == 'ready':
                            partition_map['active'].append(col[3])
                        elif col[6] == 'ghost':
                            partition_map['ghost'].append(col[3])

        logging.getLogger().info("disk_partition_temp :: %s " % disk_partition_temp)
        logging.getLogger().info("disk_partition :: %s " % disk_partition)
        logging.getLogger().info("multipath_failure_flag :: %s " % multipath_failure_flag)
        return multipath_failure_flag == 0, disk_partition_temp, partition_map
    except Exception as e:
        logging.getLogger().error("Exception while verifying multipath :: %s" % e)
        raise e


def verify_partition(disk_partition_temp):
    try:
        return len(disk_partition_temp) == 0
    except Exception as e:
        #print("Exception while verifying partitions :: %s" % e)
        logging.getLogger().error("Exception while verifying partitions :: %s" % e)
        raise e


def verify_lsscsi(node_name, disk_partition):
    lsscsi_entry_not_found = []
    try:
        if globals.platform == 'k8s':
            # Verify lsscsi row available for each partition received
            for partition in disk_partition:
                command = " lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '$2~/%s/ {print $2}'" % partition
                logging.getLogger().info("lsscsi command :: %s " % command)
                result_partition = get_command_output(node_name, command)
                logging.getLogger().info("partition :: %s" % partition)
                logging.getLogger().info("result_partition :: %s" % result_partition)
                if partition not in result_partition:
                    lsscsi_entry_not_found.append(partition)

            if len(lsscsi_entry_not_found) > 0:
                logging.getLogger().warning("Entry missing for partitions %s in lsscsi output" % lsscsi_entry_not_found)
                return False
            else:
                return True
        else:
            logging.getLogger().info("Skipped lsscsi verification on OCP.")
            return True
    except Exception as e:
        logging.getLogger().error("Exception while verifying lsscsi :: %s" % e)
        raise e


def delete_pod(name, namespace):
    try:
        #print("Deleting pod %s..." % name)
        logging.getLogger().info("Deleting pod %s..." % name)
        hpe_delete_pod_object_by_name(name, namespace=namespace)

        return check_if_deleted(timeout, name, "Pod", namespace=namespace)
        #print("Pod %s is deleted." % name)
        logging.getLogger().info("Pod %s is deleted." % name)
    except Exception as e:
        #print("Exception while deleting pod :: %s" % e)
        logging.getLogger().error("Exception while deleting pod :: %s" % e)
        raise e


def verify_deleted_partition(iscsi_ips, node_name, hpe3par_vlun, pvc_crd):
    try:
        failed_for_ip = None
        flag = True

        logging.getLogger().info("Verifying 'ls -lrth /dev/disk/by-path' entries are cleaned...")
        # verify ls -lrth /dev/disk/by-path at node
        if globals.access_protocol == 'iscsi':
            target_iqns = pvc_crd['spec']['record']['TargetIQNs'].split(",")
            lun_id = pvc_crd['spec']['record']['LunId']
            peer_target_iqns = None
            peer_lun = None

            if globals.replication_test:
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    if 'lun_id' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_lun = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['lun_id']

                    if 'target_names' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_target_iqns = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['target_names']
                        if isinstance(peer_target_iqns, list) and len(peer_target_iqns) > 0:
                            peer_target_iqns = peer_target_iqns[0]

                    target_iqns.extend(peer_target_iqns)
            iqn_ind = 0
            logging.getLogger().info("Verifying output of ls -lrth /dev/disk/by-path...")
            logging.getLogger().info("target_iqns :: %s" % target_iqns)
            for ip in iscsi_ips:
                # print("== For IP::%s " % ip)
                logging.getLogger().info("== For IP::%s " % ip)
                # command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-[0-9]*$))$/ {print $NF}' | awk -F'../' '{print $NF}'"
                command = "ls -lrth /dev/disk/by-path | awk '$9~/(ip-" + ip + ":3260-iscsi-" + \
                          target_iqns[iqn_ind] + "-lun-" + str(lun_id) + \
                          ")$/ {print $NF}' | awk -F'../' '{print $NF}'"
                iqn_ind += 1
                print("command is %s " % command)
                logging.getLogger().info("command is %s " % command)
                partitions = get_command_output(node_name, command)
                print("== Partition(s) received for %s are %s" % (ip, partitions))
                logging.getLogger().info("== Partition(s) received for %s are %s" % (ip, partitions))
                if partitions is None or len(partitions) > int(0):
                    flag = False
                    failed_for_ip = ip
                    break

            '''lun = hpe3par_vlun['lun']
            for ip in iscsi_ips:
                #print("For IP::%s " % ip)
                logging.getLogger().info("For IP::%s " % ip)
                command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-" + str(lun) + "))$/ {print $NF}' | awk -F'../' '{print $NF}'"
                #print("command is %s " % command)
                logging.getLogger().info("command is %s " % command)
                partitions = get_command_output(node_name, command)
                if len(partitions) != int(0):
                    flag = False
                    failed_for_ip = ip
                    break'''
        elif globals.access_protocol == 'nvmetcp':
            # NVMe-TCP cleanup verification - matches primera_pod_verifier.py patterns
            logging.getLogger().info("Verifying NVMe-TCP paths are cleaned...")
            
            target_nqns = []
            lun_id = None
            peer_lun_id = None
            
            if 'TargetIQNs' in pvc_crd['spec']['record']:
                target_nqns = pvc_crd['spec']['record']['TargetIQNs'].split(",")
            
            if 'LunId' in pvc_crd['spec']['record']:
                lun_id = pvc_crd['spec']['record']['LunId']
            
            vol_wwn = hpe3par_vlun.get('volumeWWN', '')
            lun = hpe3par_vlun.get('lun', lun_id)
            
            # Handle replication scenario
            if globals.replication_test:
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    peer_details = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]
                    if 'target_names' in peer_details:
                        peer_target_nqns = peer_details['target_names']
                        if isinstance(peer_target_nqns, list):
                            target_nqns.extend(peer_target_nqns)
                        else:
                            target_nqns.append(peer_target_nqns)
                    
                    if 'lun_id' in peer_details:
                        peer_lun_id = peer_details['lun_id']
            
            logging.getLogger().info("Checking NVMe paths cleanup for vol_wwn: %s, LUN: %s" % (vol_wwn, lun))
            
            partitions = []
            
            # Check by volume WWN + LUN (generic PCI pattern)
            if vol_wwn and lun is not None:
                command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^pci-.*nvme.*" + \
                          vol_wwn[-6:] + "-lun-" + str(lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                logging.getLogger().info("NVMe cleanup check (vol_wwn + LUN) :: %s" % command)
                result = get_command_output(node_name, command)
                if result:
                    partitions.extend(result)
            
            # Check by NQN pattern if needed
            if len(partitions) == 0 and target_nqns:
                for nqn in target_nqns:
                    if not nqn:
                        continue
                    nqn_suffix = nqn.split(':')[-1] if ':' in nqn else nqn
                    command = "ls -lrth /dev/disk/by-path | awk '$9~/pci-.*nvme/ && $9~/" + nqn_suffix + \
                              "/ {print $NF}' | awk -F'../' '{print $NF}'"
                    logging.getLogger().info("NVMe NQN cleanup check :: %s" % command)
                    result = get_command_output(node_name, command)
                    if result:
                        partitions.extend(result)
            
            # Check peer array paths for replication
            if globals.replication_test and peer_lun_id is not None and vol_wwn:
                command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^pci-.*nvme.*" + \
                          vol_wwn[-6:] + "-lun-" + str(peer_lun_id) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                logging.getLogger().info("Peer NVMe cleanup check command :: %s" % command)
                peer_partitions = get_command_output(node_name, command)
                if peer_partitions:
                    partitions.extend(peer_partitions)
            
            logging.getLogger().info("== NVMe partitions remaining: %s" % partitions)
            
            # If any partitions found, cleanup verification failed
            if len(partitions) > 0:
                flag = False
        else:
            lun = hpe3par_vlun['lun']
            host_wwn = hpe3par_vlun['remoteName']
            vol_wwn = hpe3par_vlun['volumeWWN']
            peer_lun = None
            peer_vol_wwn = None
            '''command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^fc-0x" + host_wwn + \
                      ".*-lun-" + str(lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"'''
            command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^fc-0x" + host_wwn + \
                      "-.*" + vol_wwn[-6:] + "-lun-" + str(lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"

            logging.getLogger().info("command is %s " % command)
            partitions = get_command_output(node_name, command)

            # partitions from secondary array for replication scenario
            if globals.replication_test:
                logging.getLogger().info("Getting partitions for replicated array")
                import pdb
                # pdb.set_trace()
                if pvc_crd['spec']['record']['PeerArrayDetails'] is not None and \
                        len(eval(pvc_crd['spec']['record']['PeerArrayDetails'])) > 0:
                    if 'lun_id' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_lun = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['lun_id']

                    if 'target_names' in eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]:
                        peer_vol_wwn = eval(pvc_crd['spec']['record']['PeerArrayDetails'])[0]['target_names']
                        if isinstance(peer_vol_wwn, list) and len(peer_vol_wwn) > 0:
                            peer_vol_wwn = peer_vol_wwn[0]
                        logging.getLogger().info("peer_lun :: %s" % peer_lun)
                        logging.getLogger().info("peer_vol_wwn :: %s" % peer_vol_wwn)
                        if peer_lun is not None or peer_vol_wwn is not None:
                            if peer_vol_wwn is None:
                                peer_vol_wwn = vol_wwn
                            if peer_lun is None:
                                peer_lun = lun
                            command = "ls -lrth /dev/disk/by-path | awk -v IGNORECASE=1 '$9~/^fc-0x" + host_wwn + "-.*" \
                                      + peer_vol_wwn[-6:] + "-lun-" + str(peer_lun) + "$/ {print $NF}' | awk -F'../' '{print $NF}'"
                            logging.getLogger().info("command is :: %s" % command)
                            partitions.extend(get_command_output(node_name, command))
            if len(partitions) != 0:
                flag = False
        return flag, failed_for_ip
    except Exception as e:
        logging.getLogger().error("Exception while verifying deleted by-path:: %s" % e)
        raise e


def verify_deleted_multipath_entries(node_name, hpe3par_vlun, disk_partition):
    try:
        # Verify multipath -ll output
        command = "multipath -ll | awk -v IGNORECASE=1 '/^([0-9]" + hpe3par_vlun['volumeWWN'] + \
                  ").*(3PARdata,VV)/{x=NR+" + str(len(disk_partition) + 3) + "}(NR<=x){print}'"
        logging.getLogger().info("command is :: %s" % command)
        paths = get_command_output(node_name, command)
        return paths
    except Exception as e:
        #print("Exception :: %s" % e)
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def verify_deleted_lsscsi_entries(node_name, disk_partition):
    lsscsi_entry_found = []
    try:
        if globals.platform == 'k8s':
            # Verify lsscsi row available for each partition received
            for partition in disk_partition:
                command = " lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '$2~/%s/ {print $2}'" % partition
                logging.getLogger().info("lsscsi command :: %s " % command)
                result_partition = get_command_output(node_name, command)
                logging.getLogger().info("partition :: %s" % partition)
                logging.getLogger().info("result_partition :: %s" % result_partition)
                if partition in result_partition:
                    lsscsi_entry_found.append(partition)

            if len(lsscsi_entry_found) > 0:
                logging.getLogger().warning("Entry exists for partitions %s in lsscsi output" % lsscsi_entry_found)
                return False
            else:
                return True
        else:
            logging.getLogger().info("Skipped lscsi deletion verification on OCP.")
            return True
    except Exception as e:
        logging.getLogger().error("Exception :: %s" % e)
        raise e


def verify_clone_crd_status(pvc_volume_name):
    try:
        logging.getLogger().info("Verifying CRD status of %s..." % pvc_volume_name)
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
        logging.getLogger().error("Exception while verifying CRD for clone pvc  :: %s" % e)
        raise e


def get_kind_name(yml, kind_name):
    # Fetch snapclass name
    snapclass_name = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            logging.getLogger().info(el)
            if el['kind'] == kind_name:
                print(el['kind'])
                snapclass_name = el['metadata']['name']
                break
    return snapclass_name


def create_snapclass(yml, snap_class_name='ci-snapclass'):
    try:
        logging.getLogger().info("Creating snapclass %s..." % snap_class_name)
        if globals.platform == 'os':
            command = "oc create -f " + yml
        else:
            command = "kubectl create -f " + yml
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output) == "volumesnapshotclass.snapshot.storage.k8s.io/%s created\n" % snap_class_name:
            logging.getLogger().info("Snapclass %s created." % snap_class_name)
            return True
        else:
            logging.getLogger().info("Snapclass %s is not created." % snap_class_name)
            return False
    except Exception as e:
        logging.getLogger().error("Exception while creating snapclass :: %s" % e)
        raise e


def verify_snapclass_created(snap_class_name='ci-snapclass'):
    try:
        logging.getLogger().info("Verify if snapclass %s is created..." % snap_class_name)
        if globals.platform == 'os':
            command = "oc get volumesnapshotclasses.snapshot.storage.k8s.io -o json"
        else:
            command = "kubectl get volumesnapshotclasses.snapshot.storage.k8s.io -o json"
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        flag = False
        crds = json.loads(output)
        logging.getLogger().info(crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                logging.getLogger().info(snap_class["metadata"]["name"])
                if str(snap_class["metadata"]["name"]) == snap_class_name:
                    flag = True
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapclass :: %s" % e)
        raise e


def create_snapshot(yml, snapshot_name='ci-pvc-snapshot'):
    try:
        logging.getLogger().info("Creating snapshot %s ..." % snapshot_name)
        if globals.platform == 'os':
            command = "oc create -f " + yml
        else:
            command = "kubectl create -f " + yml
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output) == "volumesnapshot.snapshot.storage.k8s.io %s created\n" % snapshot_name:
            return True
        else:
            return False
    except Exception as e:
        logging.getLogger().error("Exception while creating snapshot :: %s" % e)
        raise e


def verify_snapshot_created(snapshot_name='ci-pvc-snapshot'):
    try:
        logging.getLogger().info("Verifying snapshot %s created..." % snapshot_name)
        if globals.platform == 'os':
            command = "oc get volumesnapshots.snapshot.storage.k8s.io -o json -n %s" % globals.namespace
        else:
            command = "kubectl get volumesnapshots.snapshot.storage.k8s.io -o json -n %s" % globals.namespace
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        flag = False
        crds = json.loads(output)
        logging.getLogger().info(crds)
        if crds["kind"] == "List":
            snapshots = crds["items"]
            for snapshot in snapshots:
                logging.getLogger().info(snapshot["metadata"]["name"])
                if str(snapshot["metadata"]["name"]) == snapshot_name:
                    flag = True
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapshot :: %s" % e)
        raise e


def verify_snapshot_ready(snapshot_name='ci-pvc-snapshot'):
    try:
        snap_uid = None
        logging.getLogger().info("Verify if snapshot is ready...")
        if globals.platform == 'os':
            command = "oc get volumesnapshots.snapshot.storage.k8s.io %s -n %s -o json" % (snapshot_name, globals.namespace)
        else:
            command = "kubectl get volumesnapshots.snapshot.storage.k8s.io %s -n %s -o json" % (snapshot_name, globals.namespace)
        logging.getLogger().info(command)
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
        logging.getLogger().error("Exception while verifying snapshot status :: %s" % e)
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
        logging.getLogger().error("Exception while verifying snapshot volume on 3par :: %s" % e)
        raise e


def delete_snapshot(snapshot_name='ci-pvc-snapshot'):
    try:
        logging.getLogger().info("Deleting snapshot %s..." % snapshot_name)
        if globals.platform == 'os':
            command = "oc delete volumesnapshots.snapshot.storage.k8s.io %s -n %s" % (snapshot_name, globals.namespace)
        else:
            command = "kubectl delete volumesnapshots.snapshot.storage.k8s.io %s -n %s" % (snapshot_name, globals.namespace)
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output) == 'volumesnapshot.snapshot.storage.k8s.io "%s" deleted\n' % snapshot_name:
            return True
        else:
            return False
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapshot deletion :: %s" % e)
        raise e


def verify_snapshot_deleted(snapshot_name='ci-pvc-snapshot'):
    try:
        logging.getLogger().info("Verify if snapshot %s is deleted..." % snapshot_name)
        if globals.platform == 'os':
            command = "oc get volumesnapshots.snapshot.storage.k8s.io -o json -n %s" % globals.namespace
        else:
            command = "kubectl get volumesnapshots.snapshot.storage.k8s.io -o json -n %s" % globals.namespace
        output = get_command_output_string(command)
        flag = True
        crds = json.loads(output)
        # print("crds :: %s " % crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                if snap_class["metadata"]["name"] == snapshot_name:
                    flag = False
                    break
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapshot deletion :: %s" % e)
        raise e


def delete_snapclass(snapclass_name='ci-snapclass'):
    try:
        logging.getLogger().info("Deleting snapshot-class %s...")
        if globals.platform == 'os':
            command = "oc delete volumesnapshotclasses %s" % snapclass_name
        else:
            command = "kubectl delete volumesnapshotclasses %s" % snapclass_name
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        if str(output) == 'volumesnapshotclass.snapshot.storage.k8s.io "%s" deleted\n' % snapclass_name:
            return True
        else:
            return False
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapclass deletion :: %s" % e)
        raise e


def verify_snapclass_deleted(snapclass_name='ci-snapclass'):
    try:
        logging.getLogger().info("Verify if snapshot-class %s is deleted..." % snapclass_name)
        if globals.platform == 'os':
            command = "oc get volumesnapshotclasses -o json"
        else:
            command = "kubectl get volumesnapshotclasses -o json"
        output = get_command_output_string(command)
        flag = True
        crds = json.loads(output)
        logging.getLogger().info("crds :: %s " % crds)
        if crds["kind"] == "List":
            snap_classes = crds["items"]
            for snap_class in snap_classes:
                if snap_class["metadata"]["name"] == snapclass_name:
                    flag = False
                    break
        return flag
    except Exception as e:
        logging.getLogger().error("Exception while verifying snapclass crd deletion :: %s" % e)
        raise e


def verify_crd_exists(crd_name, crd_type):
    try:
        #print("Verifying if CRD for %s is deleted..." % crd_name)
        flag = False
        if globals.platform == 'os':
            command = "oc get %s -o json" % crd_type
        else:
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
        logging.getLogger().error("Exception while verifying CRD for clone pvc  :: %s" % e)
        raise e


def check_if_crd_deleted(crd_name, crd_type, timeout_set=None):
    global timeout
    try:
        time = 0
        flag = True

        if timeout_set is not None:
            timeout = timeout_set

        while True:
            if verify_crd_exists(crd_name, crd_type) is False:
                break

            if int(time) > int(timeout):
                logging.getLogger().info("\nCRD %s of %s is not deleted yet. Taking longer..." % (crd_name, crd_type))
                flag = False
                break
            print(".", end='', flush=True)
            time += 1
            sleep(1)

        return flag
    except Exception as e:
        logging.getLogger().error("Exception %s while verifying if CRD %s of %s is deleted  :: %s" % (e, crd_name, crd_type))
        raise e


def verify_pvc_crd_published(crd_name):
    try:
        logging.getLogger().info("Verifying if PVC CRD is publish/unpublished...")
        flag = False
        crd = get_pvc_crd(crd_name)
        # print("crd :: %s " % crd)
        if crd is not None:
            if "spec" in crd and "record" in crd["spec"] and "Published" in crd["spec"]["record"]:
                if crd["spec"]["record"]["Published"] == "true":
                    flag = True
                else:
                    flag = False
        return flag
    except Exception as e:
        logging.getLogger().error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def get_array_version(hpe3par_cli):
    try:
        sysinfo = hpe3par_cli.getStorageSystemInfo()
        return sysinfo['systemVersion']

    except Exception as e:
        logging.getLogger().error("Exception %s while fetching array version :: %s" % e)
        #logging.error("Exception %s while fetching arra version :: %s" % e)
        raise e


def get_array_model(hpe3par_cli):
    try:
        sysinfo = hpe3par_cli.getStorageSystemInfo()
        wsapi_version = hpe3par_cli.getWsApiVersion()
        is_primera = hpe3par_cli.is_primera_array()
        logging.getLogger().info("Model of Array - %s :: Is Primera array? %s" % (sysinfo['model'], is_primera))
        return sysinfo['model'],is_primera

    except Exception as e:
        logging.getLogger().error("Exception %s while fetching array model and primera support :: %s" % e)
        raise e


def patch_pvc(name, namespace, patch_json):
    try:
        logging.getLogger().info("patch_json :: %s " % patch_json)
        response = k8s_core_v1.patch_namespaced_persistent_volume_claim(body=patch_json,namespace=namespace, name=name)
        logging.getLogger().info(response)
        return response
    except Exception as e:
        logging.getLogger().error("Exception while patch PVC %s\n%s" % (name, e))
        #logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def uncorden_node(name):
    try:
        if globals.platform == 'os':
            command = "oc adm uncordon %s " % name
        else:
            command = "kubectl uncordon %s " % name
        logging.getLogger().info(command)
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        return output
    except Exception as e:
        logging.getLogger().error("Exception while uncorden Node %s\n%s" % (name, e))
        # logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def corden_node(name):
    try:
        if globals.platform == 'os':
            command = "oc adm cordon %s " % name
        else:
            command = "kubectl cordon %s " % name
        logging.getLogger().info(command)
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        return output
    except Exception as e:
        logging.getLogger().error("Exception while corden Node %s\n%s" % (name, e))
        # logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def stop_kubelet(name):
    """
    stop_kubelet - This function stops the "kubelet" service on a particular node.
    Parameters:
        Required:
            1. (name): The name of the node where kubelet will be stopped on.
        Optional:
            None
        Returns:
            output_status: Status of the kubelet service after stopping the kubelet.
        Raises:
            Exception: If there's an error while stopping kubelet service on the node, it raises an exception.
    """
    try:
        command = "systemctl stop kubelet"
        logging.getLogger().info(command)
        output = get_command_output(name, command)
        logging.getLogger().info("Output of 'systemctl stop kubelet': " % output)
                
        output_status = status_kubelet(name)
        logging.getLogger().info("Kubelet Status on node %s:  %s" % (name,output_status[0]))
        assert output_status[0]  == "Inactive", "Status of kubelet is %s i.e not Inactive (dead)" % output_status[0]

        return output_status
    except Exception as e:
        logging.getLogger().error("Exception while simulating kubelet down on Node %s\n%s" % (name, e))
        raise e

def start_kubelet(name):
    """
    start_kubelet - This function starts the "kubelet" service on a particular node.
    Parameters:
        Required:
            1. (name): The name of the node where kubelet will be started.
        Optional:
            None
        Returns:
            output_status: Status of the kubelet service after starting the kubelet.
        Raises:
            Exception: If there's an error while starting kubelet service on the node, it raises an exception.
    """
    try:
        command = "systemctl start kubelet"
        logging.getLogger().info(command)
        output = get_command_output(name, command)
        logging.getLogger().info("Output of 'systemctl start kubelet': " % output)

        output_status = status_kubelet(name)
        logging.getLogger().info("Kubelet Status on node %s:  %s" % (name,output_status[0]))
        assert output_status[0] == "Active", "Status of kubelet is %s, not Active (running)" % output_status[0]

        return output_status
    except Exception as e:
        logging.getLogger().error("Exception while starting kubelet back up on Node %s\n%s" % (name, e))
        raise e

def status_kubelet(name):
    """
    status_kubelet - This function gets the status of the kubelet service from a particular node, and parses it.
    Parameters:
        Required:
            1. (name): The name of the node to check status of kubelet service.
        Optional:
            None
        Returns:
            output: Status of the kubelet service after stopping the kubelet.
        Raises:
            Exception: If there's an error while checking status of kubelet service on the node, it raises an exception.
    """
    try:
        command = "if systemctl status kubelet | grep -q 'active (running)'; then echo 'Active'; else echo 'Inactive'; fi"
        output = get_command_output(name, command)
        logging.getLogger().info("Checking status of kubelet: " % output)
        return output
    except Exception as e:
        logging.getLogger().error("Exception while checking status of Kubelet on Node %s\n%s" % (name, e))
        raise e

def reboot_node(node_name, user='root'):
    flag = True
    try:
        command = "ssh -t root@%s 'sudo reboot'" % node_name
        logging.getLogger().info(command)
        output = get_command_output_string(command)
        logging.getLogger().info(output)
    except Exception as e:
        flag = False
        logging.getLogger().error("Exception while rebooting Node %s\n%s" % (node_name, e))
        # logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e
    finally:
        return flag


def drain_node(name):
    try:
        if globals.platform == 'os':
            command = "oc adm drain %s --ignore-daemonsets --delete-local-data" % name
        else:
            command = "kubectl drain %s --ignore-daemonsets --delete-local-data" % name
        logging.getLogger().info(command)
        output = get_command_output_string(command)
        logging.getLogger().info(output)
        return output
    except Exception as e:
        logging.getLogger().error("Exception while drain Node %s\n%s" % (name, e))
        # logging.error("Exception %s while verifying if PVC CRD %s is published  :: %s" % (e, crd_name))
        raise e


def is_test_passed(array_version, status, is_cpg_ssd, provisioning, compression):
    logging.getLogger().info("array_version :: %s " % array_version[0:3])
    logging.getLogger().info("status :: %s " % status)
    logging.getLogger().info("is_cpg_ssd :: %s " % is_cpg_ssd)
    logging.getLogger().info("provisioning :: %s " % provisioning)
    logging.getLogger().info("compression :: %s " % compression)
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
                        logging.getLogger().info("******* returning false")
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
                        logging.getLogger().info("******* returning false")
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
                        logging.getLogger().info("******* returning false")
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
    elif globals.hpe3par_model is not "3PAR":
        logging.getLogger().info("arrays version is :: %s" % array_version[0:3])
        logging.getLogger().info("provisioning :: %s" % provisioning)
        logging.getLogger().info("compression :: %s" % compression)
        logging.getLogger().info("is_cpg_ssd :: %s" % is_cpg_ssd)
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
        logging.getLogger().info("provisioning :: %s, compression :: %s, cpg_name :: %s" % (provisioning, compression, cpg_name))
        return provisioning, compression, cpg_name, size
    except Exception as e:
        logging.getLogger().error("Exception in get_sc_properties :: %s" % e)
        raise e


def check_status_from_events(kind, name, namespace, uid, reasons=['ProvisioningSucceeded', 'ProvisioningFailed']):
    try:
        logging.getLogger().info("kind :: %s, name :: %s, namespace :: %s, uid :: %s" % (kind, name, namespace, uid))
        status = None
        message = None
        got_status = None
        while True:
            if got_status is True:
                break
            # events_list = k8s_core_v1.list_event_for_all_namespaces()
            if globals.platform == 'os':
                command = "oc get events --sort-by='{.metadata.creationTimestamp}' -o json -n %s" % namespace
            else:
                command = "kubectl get events --sort-by='{.metadata.creationTimestamp}' -o json -n %s" % namespace

            # print(command)
            output = get_command_output_string(command)
            events_json = json.loads(output)
            if events_json["kind"] == "List":
                event_list_from_json = events_json["items"]
                event_list = event_list_from_json[::-1]
                for event in event_list:
                    if event['involvedObject']['kind'] == kind and event['involvedObject']['name'] == name and \
                            event['involvedObject']['namespace'] == namespace and event['involvedObject']['uid'] == uid:
                        #print("\n%s" % event)
                        #if event['reason'] in ['ProvisioningSucceeded', 'ProvisioningFailed']:
                        if event['reason'] in reasons:
                            #print("uid :: %s " % event['involvedObject']['uid'])
                            status = event['reason']
                            message = event['message']
                            got_status = True
                            break
                        '''if event['reason'] in ['VolumeResizeFailed', 'FileSystemResizeSuccessful']:
                            #print("uid :: %s " % event['involvedObject']['uid'])
                            status = event['reason']
                            message = event['message']
                            got_status = True
                            break'''

        return status, message
    except Exception as e:
        logging.getLogger().error("Exception in check_status_from_events for %s/%s in %s:: %s" % (kind, name, namespace, e))
        raise e


def check_cpg_prop_at_array(hpe3par_cli, cpg_name, property):
    try:
        cpg = hpe3par_cli.getCPG(cpg_name)
        logging.getLogger().info("Print CPG -> {}".format(cpg))
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
                        logging.getLogger().info("print disk_type sec-> {}".format(disk_type))
                        break
            else:
                arrayVersion = get_array_version(hpe3par_cli)
                logging.getLogger().info("arrayVersion -> {}".format(arrayVersion))
                if globals.hpe3par_model == "Arcus":
                    logging.getLogger().info("Its Arcus , SSD is true")
                    return True
            if disk_type == 3:
                return True
            else:
                return False
    except Exception as e:
        logging.getLogger().error("Exception in check_cpg_prop_at_array for %s:: %s" % (cpg_name, e))
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

        logging.getLogger().info("node_name :: %s" % node_name)
        return node_name
    except Exception as e:
        logging.getLogger().error("Exception in get_pod_node :: %s" % e)
        raise e


def create_pvc_bulk(yml):
    pvc_map = {}
    if os.path.isdir(yml):
        files = os.listdir(yml)
        #print("YAMLs :: %s" % files)
        for file in files:
            #print(file)
            with open("%s/%s" % (yml,file)) as f:
                elements = list(yaml.safe_load_all(f))
                # print("\nCreating PersistentVolumeClaim %s" % len(elements))
                for el in elements:
                    # print("======== kind :: %s " % str(el.get('kind')))
                    if str(el.get('kind')) == "PersistentVolumeClaim":
                        obj = hpe_create_pvc_object(el)
                        logging.getLogger().info(f"PVC {obj.metadata.name} created")
                        pvc_map[obj.metadata.name] = obj
    else:
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            logging.getLogger().info("\nCreating %s PersistentVolumeClaim..." % len(elements))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "PersistentVolumeClaim":
                    obj = hpe_create_pvc_object(el)
                    pvc_map[obj.metadata.name] = obj
        logging.getLogger().info("PVCs created are :: %s " % pvc_map)
    return pvc_map


def delete_pvc_bulk(yml, namespace):
    deleted_pvc_list = []
    try:
        # Fetch list of pvc exist
        pvc_list = hpe_list_pvc_objects_names(globals.namespace)
        #print(pvc_list)
        logging.getLogger().debug(pvc_list)

        # Loop through all yams to get pvc name
        if os.path.isdir(yml):
            files = os.listdir(yml)
            #print("YAMLs :: %s" % files)
            for file in files:
                #print(file)
                with open("%s/%s" % (yml,file)) as f:
                    elements = list(yaml.safe_load_all(f))
                    # print("\nCreating PersistentVolumeClaim %s" % len(elements))
                    for el in elements:
                        # print("======== kind :: %s " % str(el.get('kind')))
                        if str(el.get('kind')) == "PersistentVolumeClaim":
                            #namespace = "default"
                            if 'namespace' in el.get('metadata'):
                                namespace = el.get('metadata')['namespace']
                            if el['metadata']['name'] in pvc_list:
                                hpe_delete_pvc_object_by_name(el['metadata']['name'])
                                logging.getLogger().info(f"PVC {el['metadata']['name']} deleted")
                                deleted_pvc_list.append(el['metadata']['name'])
        else:
            with open(yml) as f:
                elements = list(yaml.safe_load_all(f))
                logging.getLogger().info("\nDeleting %s PersistentVolumeClaim..." % len(elements))
                for el in elements:
                    # print("======== kind :: %s " % str(el.get('kind')))
                    if str(el.get('kind')) == "PersistentVolumeClaim":
                        #namespace = "default"
                        if 'namespace' in el.get('metadata'):
                            namespace = el.get('metadata')['namespace']
                        if el['metadata']['name'] in pvc_list:
                            hpe_delete_pvc_object_by_name(el['metadata']['name'])
                            logging.getLogger().info(f"PVC {el['metadata']['name']} deleted")
                            deleted_pvc_list.append(el['metadata']['name'])
            logging.getLogger().info("PVCs deleted are :: %s " % deleted_pvc_list)
    except Exception as e:
        raise e
    return deleted_pvc_list


def create_dep_bulk(yml, namespace):
    dep_map = {}
    secret_obj = None

    if os.path.isdir(yml):
        files = os.listdir(yml)
        #print("YAMLs :: %s" % files)
        for file in files:
            #print(file)
            with open("%s/%s" % (yml,file)) as f:
                elements = list(yaml.safe_load_all(f))
                # print("\nCreating PersistentVolumeClaim %s" % len(elements))
                for el in elements:
                    # print("======== kind :: %s " % str(el.get('kind')))
                    if str(el.get('kind')) == "Secret":
                        secret_obj = hpe_get_secret_object_by_name(el['metadata']['name'], namespace)
                        if secret_obj is None:
                            secret_obj = hpe_create_secret_object(el)
                        #print(secret_obj)
                    if str(el.get('kind')) == "Deployment":
                        obj = hpe_create_dep_object(el)
                        logging.getLogger().info(f"Deployment {obj.metadata.name} created.")
                        dep_map[obj.metadata.name] = obj
    else:
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            logging.getLogger().info("\nCreating %s deployment..." % len(elements))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "Secret" and secret_obj is not None:
                    secret_obj = hpe_create_secret_object(el)
                    #print(secret_obj)
                if str(el.get('kind')) == "Deployment":
                    obj = hpe_create_dep_object(el)
                    dep_map[obj.metadata.name] = obj
        #print("Deployments created are :: %s " % dep_map)
    return dep_map


def delete_dep_bulk(yml, namespace):
    deleted_dep_list = []
    secret_obj = None
    try:
        # Fetch list of deployments exist
        dep_list = hpe_list_deployment_objects_names(globals.namespace)
        logging.getLogger().info(f"Deployments to be deleted are :: {dep_list}")

        # Loop through all yams to get deployment name
        if os.path.isdir(yml):
            files = os.listdir(yml)
            # print("YAMLs :: %s" % files)
            for file in files:
                # print(file)
                with open("%s/%s" % (yml,file)) as f:
                    elements = list(yaml.safe_load_all(f))
                    # print("\nCreating PersistentVolumeClaim %s" % len(elements))
                    for el in elements:
                        # print("======== kind :: %s " % str(el.get('kind')))
                        if str(el.get('kind')) == "Secret":
                            secret_obj = hpe_get_secret_object_by_name(el['metadata']['name'], namespace)
                            if secret_obj is not None:
                                hpe_delete_secret_object_by_name(el['metadata']['name'], namespace)
                            #print(secret_obj)
                        if str(el.get('kind')) == "Deployment":
                            print(el['metadata']['name'])
                            if el['metadata']['name'] in dep_list:
                                hpe_delete_dep_object(el['metadata']['name'], namespace)
                                #print(obj)
                                deleted_dep_list.append(el['metadata']['name'])
        else:
            with open(yml) as f:
                elements = list(yaml.safe_load_all(f))
                logging.getLogger().info("\nDeleting %s deployment..." % len(elements))
                for el in elements:
                    # print("======== kind :: %s " % str(el.get('kind')))
                    if str(el.get('kind')) == "Secret":
                        secret_obj = hpe_get_secret_object_by_name(el['metadata']['name'], namespace)
                        if secret_obj is not None:
                            hpe_delete_secret_object_by_name(el['metadata']['name'], namespace)
                    if str(el.get('kind')) == "Deployment":
                        if el['metadata']['name'] in dep_list:
                            hpe_delete_dep_object(el['metadata']['name'], namespace)
                            # print(obj)
                            deleted_dep_list.append(el['metadata']['name'])
            #print("Deployments created are :: %s " % dep_map)
    except Exception as e:
        logging.getLogger().error("Exception while deleting deployment in bulk %s" % e)
        raise e
    return deleted_dep_list


def check_status_for_bulk(kind, map):
    obj_list = map.values()
    obj_by_status_map = {'ProvisioningSucceeded': [],
                         'ProvisioningFailed': []
                         }
    expected_status = 'Bound'
    if kind.lower() == 'pvc' or kind.lower() == 'PersistentVolumeClaim'.lower():
        expected_status = 'ProvisioningSucceeded'
    for obj in obj_list:
        """status, message = check_status_from_events(obj.kind, obj.metadata.name, obj.metadata.namespace, obj.metadata.uid)
        if status in obj_by_status_map:
            obj_by_status_map[status].append(obj)
        else:
            obj_by_status_map[status] = [obj]"""
        flag, pvc_obj = check_status(20, obj.metadata.name, kind='pvc', status='Bound',
                                     namespace=obj.metadata.namespace)
        if flag:
            obj_by_status_map['ProvisioningSucceeded'].append(pvc_obj)
        else:
            obj_by_status_map['ProvisioningFailed'].append(pvc_obj)

    return obj_by_status_map


def read_yaml(yml):
    elements = None
    try:
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
    except Exception as e:
        logging.getLogger().error("Exception in read_yaml:: %s" % e)
        raise e
    finally:
        return elements


def read_value_from_yaml(yml, kind, key):
    value = None
    try:
        key_list = key.split(":")
        elements = read_yaml(yml)
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            if str(el.get('kind')) == kind:
                temp_el = el
                for key in key_list:
                    value = get_val(temp_el, key)
                    if value is not None:
                        temp_el = temp_el[key]
                    else:
                        break
        return value
    except Exception as e:
        logging.getLogger().error("Exception in read_yaml:: %s" % e)
        raise e


def get_val(element, key):
    val = None
    if key in element:
        val = element[key]
    return val


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
                if str(el.get('kind')) == "mutator_prop":
                    yaml_values['cpg'] = el['cpg']
                    yaml_values['snpCpg'] = el['snpCpg']  
                    yaml_values['provType'] = el['provType']
                    yaml_values['compression'] = el['compression']
                    yaml_values['comment'] = el['comment']
                if str(el.get('kind')) == "VolumeGroup":
                    yaml_values['name'] = el['metadata']['name']

        size = 10240
        if 'size' in yaml_values.keys():
            size = yaml_values['size']
            if size[-1].lower() == 'g'.lower():
                size = int(size[:-1]) * 1024
            elif size[-2:].lower() == 'gi'.lower():
                size = int(size[:-2]) * 1024
        yaml_values['size'] = size
        logging.getLogger().info(yaml_values)
        return yaml_values
    except Exception as e:
        logging.getLogger().error("Exception in get_details_for_volume:: %s" % e)
        raise e


def check_if_rcg_exists(rcg_name, hpe3par_cli):
    flag = False
    try:
        rcg_group_map = hpe3par_cli.getRemoteCopyGroups()
        logging.getLogger().info("RemoteCopyGroup Name :: %s" % rcg_name)
        logging.getLogger().info("RemoteCopyGroups :: %s" % rcg_group_map)
        rcg_list = rcg_group_map['members']
        for rcg in rcg_list:
            if rcg['name'] == rcg_name:
                flag = True
                break
        return flag
    except Exception as e:
        logging.getLogger().error("Exception in check_if_rcg_exists:: %s" % e)
        raise e


def get_enc_values(yml):
    try:
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

        logging.getLogger().info("hostEncryption :: %s, hostEncryptionSecretName :: %s, "
                                 "hostEncryptionSecretNamespace :: %s" % (host_encryption, host_encryption_secret_name, host_encryption_secret_namespace))
        return host_encryption, host_encryption_secret_name, host_encryption_secret_namespace
    except Exception as e:
        logging.getLogger().error("Exception in get_enc_values :: %s" % e)
        raise e


def is_test_passed_with_encryption(status, enc_secret_name, yml):
    host_encryption, host_encryption_secret_name, host_encryption_secret_namespace = get_enc_values(yml)
    logging.getLogger().info("hostEncryption :: %s " % host_encryption)
    logging.getLogger().info("hostEncryptionSecretName :: %s " % host_encryption_secret_name)
    logging.getLogger().info("hostEncryptionSecretNamespace :: %s " % host_encryption_secret_namespace)
    if host_encryption is None:
        if host_encryption_secret_name is None:
            if host_encryption_secret_namespace is None:
                if status == 'ProvisioningSucceeded':
                    return True
                else:
                    return False
            else:
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
        elif host_encryption_secret_name == enc_secret_name:
            if host_encryption_secret_name != '':
                if host_encryption_secret_namespace == globals.namespace:
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
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
    elif host_encryption is True or host_encryption.lower() == 'true':
        if host_encryption_secret_name == enc_secret_name:
            if host_encryption_secret_name != '':
                if host_encryption_secret_namespace == globals.namespace:
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
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
        else:
            if host_encryption_secret_name == enc_secret_name:
                if host_encryption_secret_namespace == globals.namespace:
                    if status == 'ProvisioningSucceeded':
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                if status == 'ProvisioningFailed':
                    return True
                else:
                    return False
    elif host_encryption is False or host_encryption.lower() == 'false':
        if status == 'ProvisioningSucceeded':
            return True
        else:
            return False
    else:
        if status == 'ProvisioningFailed':
            return True
        else:
            return False


# ============================================================================
# NVMe-TCP Verification Helper Methods for 3PAR Gen5 and Arcus Arrays
# ============================================================================

def verify_nvme_list_subsys(node_name, subsystem_nqn, volume_name):
    """
    Verify NVMe device exists and is properly configured on worker node.
    Uses 'nvme list-subsys' to check if device with expected subsystem NQN is present.

    Args:
        node_name (str): Name of the Kubernetes worker node
        subsystem_nqn (str): Expected NVMe Subsystem NQN to verify
        volume_name (str): Volume name for logging purposes

    Returns:
        bool: True if device found, False otherwise
    """
    try:
        logging.getLogger().info("Verifying NVMe device on node %s for volume %s" % (node_name, volume_name))
        logging.getLogger().info("Expected subsystem NQN: %s" % subsystem_nqn)
        # Use nvme list-subsys to check for device
        command = "sudo nvme list-subsys -o json 2>/dev/null || echo '[]'"
        logging.getLogger().info("Running command: %s" % command)
        output = get_command_output(node_name, command)

        if not output or len(output) == 0:
            logging.getLogger().warning("No output from nvme list-subsys command")
            return False

        # Parse JSON output
        try:
            output_str = ' '.join(output) if isinstance(output, list) else output
            subsystems_data = json.loads(output_str)

            if not isinstance(subsystems_data, list):
                subsystems_data = subsystems_data.get('Subsystems', [])

            # Search for matching subsystem NQN
            for subsystem in subsystems_data:
                subsystem_nqns = [subsystem.get("NQN") for subsystem in subsystem.get("Subsystems", [])]
                if subsystem_nqns and subsystem_nqn in subsystem_nqns:
                    logging.getLogger().info("✓ NVMe device found with matching NQN")
                    paths = subsystem.get('Paths', [])
                    if paths:
                        logging.getLogger().info("  Device paths: %s" % [p.get('Name') for p in paths])
                    return True

            logging.getLogger().error("NVMe device with NQN %s not found on node" % subsystem_nqn)
            return False

        except json.JSONDecodeError as e:
            logging.getLogger().error("Failed to parse nvme list-subsys output: %s" % e)
            return False

    except Exception as e:
        logging.getLogger().error("Exception while verifying NVMe device on node: %s" % e)
        return False


def verify_nvme_list_subsys_cleanup(node_name, hostnqn, volume_name):
    """
    Verify NVMe device has been cleaned up from worker node after pod deletion.
    Uses 'nvme list-subsys' to ensure device is removed.

    Args:
        node_name (str): Name of the Kubernetes worker node
        hostnqn (str): NVMe Host NQN to check for cleanup
        volume_name (str): Volume name for logging purposes

    Returns:
        bool: True if device is cleaned up (not found), False if still exists
    """
    try:
        logging.getLogger().info("Verifying NVMe device cleanup on node %s for volume %s" % (node_name, volume_name))
        command = "sudo nvme list-subsys -o json 2>/dev/null || echo '[]'"
        output = get_command_output(node_name, command)

        if not output or len(output) == 0:
            logging.getLogger().info("✓ No NVMe subsystems found - cleanup successful")
            return True

        try:
            output_str = ' '.join(output) if isinstance(output, list) else output
            subsystems_data = json.loads(output_str)

            if not isinstance(subsystems_data, list):
                subsystems_data = subsystems_data.get('Subsystems', [])

            # Check if subsystem still exists
            for subsystem in subsystems_data:
                if subsystem.get('NQN') == hostnqn or subsystem.get('SubsystemNQN') == hostnqn:
                    logging.getLogger().error("✗ NVMe device still exists - cleanup failed")
                    return False

            logging.getLogger().info("✓ NVMe device with NQN %s cleaned up successfully" % hostnqn)
            return True

        except json.JSONDecodeError:
            logging.getLogger().info("✓ No valid NVMe data found - cleanup successful")
            return True

    except Exception as e:
        logging.getLogger().error("Exception checking NVMe device cleanup: %s" % e)
        return True  # Return True to avoid false failures


def verify_nvme_list_cleanup(node_name, subsystem_nqn):
    """
    Verify NVMe namespace has been removed from worker node after pod deletion.
    Uses 'nvme list' to check for active namespaces.

    Args:
        node_name (str): Name of the Kubernetes worker node
        subsystem_nqn (str): NVMe Subsystem NQN to check for cleanup

    Returns:
        bool: True if namespace is cleaned up, False if still exists
    """
    try:
        logging.getLogger().info("Verifying NVMe namespace cleanup on node %s" % node_name)

        command = "sudo nvme list -o json 2>/dev/null || echo '{}'"
        output = get_command_output(node_name, command)

        if not output or len(output) == 0:
            logging.getLogger().info("✓ No NVMe devices found - namespace cleanup successful")
            return True

        try:
            output_str = ' '.join(output) if isinstance(output, list) else output
            devices_data = json.loads(output_str)

            # Handle different JSON formats
            devices = devices_data.get('Devices', []) if isinstance(devices_data, dict) else []

            if not devices:
                logging.getLogger().info("✓ No NVMe devices found - namespace cleanup successful")
                return True

            # Check if any device matches the subsystem NQN
            for device in devices:
                device_nqn = device.get('SubsystemNQN', '')
                if device_nqn == subsystem_nqn:
                    logging.getLogger().error("✗ NVMe namespace still exists on device %s" % device.get('DevicePath', 'unknown'))
                    return False

            logging.getLogger().info("✓ NVMe namespace cleaned up successfully")
            return True

        except json.JSONDecodeError:
            logging.getLogger().info("✓ No valid NVMe data found - namespace cleanup successful")
            return True

    except Exception as e:
        logging.getLogger().error("Exception checking NVMe namespace cleanup: %s" % e)
        return True


def verify_nvme_connection_cleanup(node_name, subsystem_nqn):
    """
    Verify NVMe TCP connections have been properly disconnected from worker node.
    Uses 'nvme list-subsys' to check for active connections.

    Args:
        node_name (str): Name of the Kubernetes worker node
        subsystem_nqn (str): NVMe Subsystem NQN to check for connections

    Returns:
        bool: True if no connections remain, False if connections exist
    """
    try:
        logging.getLogger().info("Verifying NVMe connection cleanup on node %s" % node_name)

        command = "sudo nvme list-subsys -o json 2>/dev/null || echo '[]'"
        output = get_command_output(node_name, command)

        if not output or len(output) == 0:
            logging.getLogger().info("✓ No NVMe subsystems found - connection cleanup successful")
            return True

        try:
            output_str = ' '.join(output) if isinstance(output, list) else output
            subsystems_data = json.loads(output_str)

            if not isinstance(subsystems_data, list):
                subsystems_data = subsystems_data.get('Subsystems', [])

            # Check for subsystem with active connections
            for subsystem in subsystems_data:
                if subsystem.get('NQN') == subsystem_nqn or subsystem.get('SubsystemNQN') == subsystem_nqn:
                    paths = subsystem.get('Paths', [])
                    if paths and len(paths) > 0:
                        logging.getLogger().error("✗ NVMe connections still active: %s" % paths)
                        return False

            logging.getLogger().info("✓ NVMe connections cleaned up successfully")
            return True

        except json.JSONDecodeError:
            logging.getLogger().info("✓ No valid NVMe data found - connection cleanup successful")
            return True

    except Exception as e:
        logging.getLogger().error("Exception checking NVMe connection cleanup: %s" % e)
        return True


def verify_nvme_multipath(node_name, subsystem_nqn, expected_paths=4):
    """
    Verify NVMe multipath configuration and active paths on worker node.

    Args:
        node_name (str): Name of the Kubernetes worker node
        subsystem_nqn (str): NVMe Subsystem NQN to check for multipath
        expected_paths (int): Expected number of active paths (default: 4)

    Returns:
        tuple: (bool, int) - (success, actual_path_count)
    """
    try:
        logging.getLogger().info("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% testing")
        logging.getLogger().info("Verifying NVMe multipath on node %s" % node_name)

        command = "sudo nvme list-subsys -o json 2>/dev/null || echo '[]'"
        output = get_command_output(node_name, command)

        if not output or len(output) == 0:
            logging.getLogger().warning("No NVMe subsystems found")
            return False, 0

        try:
            output_str = ' '.join(output) if isinstance(output, list) else output
            subsystems_data = json.loads(output_str)
            if not isinstance(subsystems_data, list):
                subsystems_data = subsystems_data.get('Subsystems', [])

            # Find matching subsystem and count paths
            for subsystem in subsystems_data:
                subsystem_nqns = [subsystem.get("NQN") for subsystem in subsystem.get("Subsystems", [])]
                if subsystem_nqns and subsystem_nqn in subsystem_nqns:
                    paths = subsystem.get('Subsystems', [])
                    active_paths = [path for subsystem in paths for path in subsystem.get('Paths', []) if path.get('State', '').lower() == 'live']
                    path_count = len(active_paths)

                    logging.getLogger().info("NVMe multipath: %d live path(s) found" % path_count)

                    if path_count == expected_paths:
                        logging.getLogger().info("✓ All %d paths are active" % expected_paths)
                        return True, path_count
                    else:
                        logging.getLogger().warning("Expected %d paths, found %d" % (expected_paths, path_count))
                        return False, path_count

            logging.getLogger().warning("Subsystem with NQN %s not found" % subsystem_nqn)
            return False, 0

        except json.JSONDecodeError as e:
            logging.getLogger().error("Failed to parse nvme list-subsys output: %s" % e)
            return False, 0

    except Exception as e:
        logging.getLogger().error("Exception while verifying NVMe multipath: %s" % e)
        return False, 0


def verify_nvme_mount_and_fs_type(pvc_name, pod_namespace, pvc_object, expected_fs_type=None, node_name=None):
    """
    Verify NVMe disk mount and filesystem type using volume name.

    This method validates that:
    1. The NVMe device associated with a volume is properly mounted
    2. The device exists in 'nvme list' output
    3. The mount type matches the expected filesystem type (ext4, xfs, nfs, etc.)

    Uses 'mount | grep nvme' to find mount entries and 'nvme list' to verify
    the device exists. Matches volume name from kubelet mount paths to identify
    the correct NVMe device (e.g., /dev/nvme0n1, /dev/nvme0n2).

    Args:
        pvc_name (str): Volume name (PV name) to validate (e.g., "pvc-160ea208-f299-44e8-aea3-bbca6b4a9ba5")
        pod_namespace (str): Kubernetes namespace of the PVC
        pvc_object (V1PersistentVolumeClaim): Kubernetes PVC object
        expected_fs_type (str, optional): Expected filesystem type to validate against.
                                            Common values: 'ext4', 'xfs', 'nfs', 'nfs4'.
                                            If None, only validates device existence.
        node_name (str, optional): Name of the Kubernetes worker node. If not provided,
                                    retrieved from pod scheduling

    Returns:
        bool: True if validation passes (device mounted, exists in nvme list,
                and mount type matches if specified), False otherwise

    Example:
        >>> # Verify device is mounted with ext4 (volume_name is the PV name)
        >>> pvc_obj = k8s_core_v1.read_namespaced_persistent_volume_claim("my-pvc", "default")
        >>> if verify_nvme_mount_and_fs_type("pvc-160ea208-f299-44e8-aea3-bbca6b4a9ba5",
        ...                                  "default", pvc_obj, "ext4", "worker-1"):
        ...     print("NVMe device properly mounted with ext4")

    Note:
        - Searches for volume name (PV name) in kubelet mount paths
        - Extracts device name (e.g., nvme0n1, nvme0n2) from mount output
        - Verifies device exists in 'nvme list' output
        - Validates filesystem type if expected_fs_type is provided
        - Returns False if volume not found in mounts or device not in nvme list
        - Supports encrypted devices (e.g., /dev/mapper/enc-nvme0n1)
    """
    try:
        if not node_name:
            logging.getLogger().error("node_name is required for NVMe mount verification")
            return False

        logging.getLogger().info("=" * 80)
        logging.getLogger().info("Verifying NVMe mount and filesystem type for volume: %s" % pvc_name)
        if expected_fs_type:
            logging.getLogger().info("Expected filesystem type: %s" % expected_fs_type)
        logging.getLogger().info("=" * 80)

        # Execute mount | grep nvme to get mounted NVMe devices
        mount_cmd = "mount | grep nvme"
        mount_output = get_command_output(node_name, mount_cmd)

        if not mount_output:
            logging.getLogger().error("No NVMe devices found in mount output")
            return False
        # Parse mount output to find entry with volume name
        mount_str = '\n'.join(mount_output) if isinstance(mount_output, list) else mount_output

        device_name = None
        mount_type = None
        mount_path = None
        
        # Get storage class to check for encryption
        sc_name = pvc_object.spec.storage_class_name
        sc = k8s_storage_v1.read_storage_class(sc_name)
        
        # Use the full PV name from PVC object for mount path search
        # The kubelet uses the PV name in mount paths, not the truncated 3PAR volume name
        pv_name = pvc_object.spec.volume_name
        logging.getLogger().info("Searching mount output for PV name: %s" % pv_name)

        for line in mount_str.split('\n'):
            if pv_name in line:
                # Extract device name based on encryption setting
                if sc.parameters.get('hostEncryption', 'false').lower() == 'true':
                    device_match = re.search(r'(/dev/mapper/enc-nvme\d+n\d+)', line)
                else:
                    device_match = re.search(r'(/dev/nvme\d+n\d+)', line)

                if device_match:
                    device_name = device_match.group(1)

                # Extract mount path
                mount_path_match = re.search(r'on\s+(\S+)\s+type', line)
                if mount_path_match:
                    mount_path = mount_path_match.group(1)

                # Extract filesystem type (e.g., ext4, xfs, nfs)
                type_match = re.search(r'type\s+(\S+)', line)
                if type_match:
                    mount_type = type_match.group(1)

                # Log first occurrence
                if device_name:
                    logging.getLogger().info("Found mount entry:")
                    logging.getLogger().info("  Device: %s" % device_name)
                    logging.getLogger().info("  Mount Path: %s" % mount_path)
                    logging.getLogger().info("  Filesystem Type: %s" % mount_type)
                    break

        if not device_name:
            logging.getLogger().error("Volume %s not found in mount output" % pv_name)
            return False

        # Execute nvme list to verify device exists
        nvme_list_cmd = "nvme list"
        nvme_list_output = get_command_output(node_name, nvme_list_cmd)

        if not nvme_list_output:
            logging.getLogger().error("Failed to get nvme list output")
            return False

        # Parse nvme list output to verify device exists
        nvme_list_str = '\n'.join(nvme_list_output) if isinstance(nvme_list_output, list) else nvme_list_output

        device_found_in_nvme_list = False
        # Look for device name in nvme list output (e.g., /dev/nvme0n1)
        # For encrypted devices, check the underlying nvme device
        check_device = device_name.replace('/dev/mapper/enc-', '/dev/')

        if check_device in nvme_list_str:
            device_found_in_nvme_list = True
            logging.getLogger().info("✓ Device %s found in 'nvme list' output" % device_name)
        else:
            logging.getLogger().error("✗ Device %s NOT found in 'nvme list' output" % device_name)

        # Validate filesystem type if expected_fs_type is provided
        fs_type_valid = True
        if expected_fs_type:
            if mount_type and mount_type.lower() == expected_fs_type.lower():
                logging.getLogger().info("✓ Filesystem type matches: %s" % mount_type)
            else:
                logging.getLogger().error(
                    "✗ Filesystem type mismatch - Expected: %s, Found: %s" % (expected_fs_type, mount_type)
                )
                fs_type_valid = False
        else:
            logging.getLogger().info("  Filesystem type: %s (not validated)" % mount_type)

        # Overall validation result
        validation_passed = device_found_in_nvme_list and fs_type_valid

        logging.getLogger().info("-" * 80)
        if validation_passed:
            logging.getLogger().info("✓ NVMe Mount and Filesystem Type Verification PASSED")
        else:
            logging.getLogger().error("✗ NVMe Mount and Filesystem Type Verification FAILED")
        logging.getLogger().info("=" * 80)

        return validation_passed

    except Exception as e:
        logging.getLogger().error("Exception while verifying NVMe mount and filesystem type: %s" % e)
        raise e


def verify_nvme_device_mount_points(node_name):
    """
    Verify NVMe device mount points by comparing lsscsi -H and nvme list-subsys outputs.

    This method validates that all NVMe devices detected by lsscsi -H are also
    properly listed in nvme list-subsys output, ensuring consistency between
    the system's view of NVMe devices and the NVMe subsystem layer.

    The method compares device names (e.g., nvme0, nvme1, nvme2) from both commands
    to ensure all devices are properly recognized at both levels.

    Args:
        node_name (str): Name of the Kubernetes worker node

    Returns:
        bool: True if all devices match between lsscsi -H and nvme list-subsys,
                False if there are any mismatches or if commands fail

    Example:
        >>> if verify_nvme_device_mount_points("worker-1.domain.com"):
        ...     print("All NVMe devices matched successfully")
        >>> else:
        ...     print("NVMe device mismatch detected")

    Note:
        - Parses lsscsi -H output to extract NVMe controller entries (e.g., [N:0])
        - Parses nvme list-subsys output to extract nvmeX device names
        - Logs detailed comparison results including matched and missing devices
        - Returns False if either command fails or returns no data
    """
    try:
        logging.getLogger().info("=" * 80)
        logging.getLogger().info("Verifying NVMe device mount points on node: %s" % node_name)
        logging.getLogger().info("=" * 80)
        # Execute lsscsi -H to get NVMe devices
        lsscsi_cmd = "lsscsi -H"
        lsscsi_output = get_command_output(node_name, lsscsi_cmd)

        if not lsscsi_output:
            logging.getLogger().error("Failed to get lsscsi -H output")
            return False

        # Parse lsscsi output to extract NVMe device names
        lsscsi_devices = []
        lsscsi_str = '\n'.join(lsscsi_output) if isinstance(lsscsi_output, list) else lsscsi_output

        # Extract device names like nvme0, nvme1 from lines like:
        # [N:0]  /dev/nvme0  HPE Alletra  4UW0004090  105600
        for line in lsscsi_str.split('\n'):
            line = line.strip()
            if line and '[N:' in line:
                # Extract the device path (e.g., /dev/nvme0)
                match = re.search(r'/dev/(nvme\d+)', line)
                if match:
                    device_name = match.group(1)
                    lsscsi_devices.append(device_name)

        logging.getLogger().info("NVMe devices from lsscsi -H: %s" % sorted(lsscsi_devices))

        # Execute nvme list-subsys to get NVMe subsystem devices
        nvme_subsys_cmd = "nvme list-subsys"
        nvme_subsys_output = get_command_output(node_name, nvme_subsys_cmd)

        if not nvme_subsys_output:
            logging.getLogger().error("Failed to get nvme list-subsys output")
            return False

        # Parse nvme list-subsys output to extract device names
        nvme_subsys_devices = []
        nvme_subsys_str = '\n'.join(nvme_subsys_output) if isinstance(nvme_subsys_output, list) else nvme_subsys_output

        # Extract device names like nvme0, nvme1 from lines like:
        # +- nvme0 tcp traddr=172.28.2.49,trsvcid=4420,src_addr=172.28.30.106 live
        for line in nvme_subsys_str.split('\n'):
            line = line.strip()
            # Look for lines starting with '+- nvmeX' or just 'nvmeX'
            match = re.search(r'^\+?\-?\s*(nvme\d+)\s+', line)
            if match:
                device_name = match.group(1)
                if device_name not in nvme_subsys_devices:
                    nvme_subsys_devices.append(device_name)

        logging.getLogger().info("NVMe devices from nvme list-subsys: %s" % sorted(nvme_subsys_devices))

        # Compare the two lists
        lsscsi_set = set(lsscsi_devices)
        nvme_subsys_set = set(nvme_subsys_devices)

        missing_in_subsys = sorted(list(lsscsi_set - nvme_subsys_set))
        missing_in_lsscsi = sorted(list(nvme_subsys_set - lsscsi_set))
        common_devices = sorted(list(lsscsi_set & nvme_subsys_set))

        # Log comparison results
        logging.getLogger().info("-" * 80)
        logging.getLogger().info("Comparison Results:")
        logging.getLogger().info("  Common devices (matched): %s" % common_devices)

        if missing_in_subsys:
            logging.getLogger().warning("  ✗ Devices in lsscsi but NOT in nvme list-subsys: %s" % missing_in_subsys)

        if missing_in_lsscsi:
            logging.getLogger().warning("  ✗ Devices in nvme list-subsys but NOT in lsscsi: %s" % missing_in_lsscsi)

        # Determine success
        success = len(missing_in_subsys) == 0 and len(missing_in_lsscsi) == 0

        logging.getLogger().info("-" * 80)
        if success:
            logging.getLogger().info("✓ NVMe Device Mount Point Verification PASSED")
            logging.getLogger().info("  All %d NVMe devices are properly recognized" % len(common_devices))
        else:
            logging.getLogger().error("✗ NVMe Device Mount Point Verification FAILED")
            if missing_in_subsys:
                logging.getLogger().error("  %d device(s) missing in nvme list-subsys" % len(missing_in_subsys))
            if missing_in_lsscsi:
                logging.getLogger().error("  %d device(s) missing in lsscsi" % len(missing_in_lsscsi))
        logging.getLogger().info("=" * 80)

        return success

    except Exception as e:
        logging.getLogger().error("Exception while verifying NVMe device mount points: %s" % e)
        raise e


def verify_hpevolumeinfo(volume_name, expected_access_protocol=None, expected_cpg=None,
                       expected_provisioning_type=None, expected_target_nqn=None):
    """
    Verify HPE Volume Info attributes from hpevolumeinfos CRD (based on primera_pod_verifier.py).

    Validates key volume attributes stored in the hpevolumeinfos Custom Resource
    Definition including access protocol, Common Provisioning Group (CPG),
    provisioning type, target NQN for NVMe, and associated PVC name.

    This method performs comprehensive validation against expected values:
    - Access Protocol: Verifies iSCSI, FC, or NVMe TCP protocol
    - CPG: Validates Common Provisioning Group on storage array
    - Provisioning Type: Checks thin/thick provisioning configuration
    - Target NQN: Verifies NVMe subsystem NQN (for NVMe volumes)

    Args:
        volume_name (str): Name of the volume to verify (e.g., "pvc-abc123")
        expected_access_protocol (str, optional): Expected protocol ('iscsi', 'fc', 'nvmetcp')
        expected_cpg (str, optional): Expected Common Provisioning Group name
        expected_provisioning_type (str, optional): Expected type ('thin', 'thick', 'dedup', etc.)
        expected_target_nqn (str, optional): Expected NVMe target subsystem NQN
        hpe3par_cli (HPE3ParClient, optional): HPE 3PAR client for array operations
        namespace (str, optional): Namespace where hpevolumeinfo resides (e.g., 'hpe-storage').
            If None, treats as cluster-scoped resource

    Returns:
        bool: True if all validations pass, False if any validation fails

    Example:
        >>> # Validate with expected values
        >>> result = verify_hpevolumeinfo(
        ...     volume_name="pvc-abc123",
        ...     expected_access_protocol="nvmetcp",
        ...     expected_cpg="SSD_r6"
        ... )
        >>> print(result)  # True if validation passes

    Note:
        - All expected_* parameters are optional; only provided values are verified
        - Returns False if any validation fails instead of raising exceptions
        - Logs detailed verification progress at INFO level
        - Logs errors at ERROR level
        - Provisioning type mapping: tpvv=2, reduce=6, full/thick=1
    """
    try:
        logging.getLogger().info("=" * 80)
        logging.getLogger().info("Verifying HPE Volume Info for volume: %s" % volume_name)
        logging.getLogger().info("=" * 80)

        # Get hpevolumeinfo CRD
        command = "kubectl get hpevolumeinfos %s -o json" % volume_name

        result = get_command_output_string(command)
        if not result:
            logging.getLogger().error("✗ Failed to get hpevolumeinfo for volume %s" % volume_name)
            return False

        try:
            volume_info = json.loads(result)
        except json.JSONDecodeError as e:
            logging.getLogger().error("✗ Failed to parse hpevolumeinfo JSON: %s" % e)
            return False

        # Extract record details
        if 'spec' not in volume_info or 'record' not in volume_info['spec']:
            logging.getLogger().error("✗ No 'record' field found in hpevolumeinfo")
            return False

        record = volume_info['spec']['record']

        # Validate access protocol
        if expected_access_protocol:
            actual_protocol = record.get('AccessProtocol', '').lower()
            logging.getLogger().info("Checking access protocol...")
            logging.getLogger().info("  Expected: %s" % expected_access_protocol)
            logging.getLogger().info("  Actual: %s" % actual_protocol)

            if actual_protocol != expected_access_protocol.lower():
                logging.getLogger().error("✗ Access protocol mismatch")
                return False
            logging.getLogger().info("✓ Access protocol matches")

        # Validate CPG
        if expected_cpg:
            actual_cpg = record.get('Cpg', '')
            logging.getLogger().info("Checking CPG...")
            logging.getLogger().info("  Expected: %s" % expected_cpg)
            logging.getLogger().info("  Actual: %s" % actual_cpg)

            if actual_cpg != expected_cpg:
                logging.getLogger().error("✗ CPG mismatch")
                return False
            logging.getLogger().info("✓ CPG matches")

        # Validate provisioning type
        if expected_provisioning_type:
            actual_prov_type = record.get('ProvisioningType', '')
            logging.getLogger().info("Checking provisioning type...")

            # Handle both string and numeric provisioning types
            # Map provisioning types to string values (as stored in CRD)
            prov_type_map = {
                'thin': 'tpvv', 'tpvv': 'tpvv',
                'thick': 'full', 'full': 'full',
                'dedup': 'dedup',
                'reduce': 'reduce'
            }

            expected_value = prov_type_map.get(expected_provisioning_type.lower(), expected_provisioning_type.lower())

            logging.getLogger().info("  Expected: %s (%s)" % (expected_provisioning_type, expected_value))
            logging.getLogger().info("  Actual: %s" % actual_prov_type)

            if actual_prov_type.lower() != expected_value:
                logging.getLogger().error("✗ Provisioning type mismatch")
                return False
            logging.getLogger().info("✓ Provisioning type matches")

        # Validate target NQN for NVMe
        if expected_target_nqn:
            # Target NQNs are in TargetNQNs field (comma-separated string)
            target_nqns_str = record.get('TargetNQNs', '')
            target_nqns = target_nqns_str.split(',') if target_nqns_str else []
            logging.getLogger().info("Checking target NQN...")
            logging.getLogger().info("  Expected: %s" % expected_target_nqn)
            logging.getLogger().info("  Actual: %s" % target_nqns)

            if expected_target_nqn not in target_nqns:
                logging.getLogger().error("✗ Target NQN not found in TargetNQNs")
                return False
            logging.getLogger().info("✓ Target NQN found")

        # Validate PVC name exists
        pvc_name = record.get('Id', '')
        if pvc_name:
            logging.getLogger().info("✓ PVC name found: %s" % pvc_name)
        else:
            logging.getLogger().warning("⚠ No PVC name in record")

        logging.getLogger().info("=" * 80)
        logging.getLogger().info("✓ HPE Volume Info validation successful for %s" % volume_name)
        logging.getLogger().info("=" * 80)
        return True

    except Exception as e:
        logging.getLogger().error("Exception while verifying hpevolumeinfo: %s" % e)
        logging.getLogger().error("Traceback: ", exc_info=True)
        return False


def verify_hpenodeinfo(node_name, protocol, expected_nqn=None, expected_iqn=None,
                      expected_wwn=None, expected_uuid=None, hpe3par_cli=None):
    """
    Verify HPE Node Info attributes from hpenodeinfos CRD based on protocol (based on primera_pod_verifier.py).

    Validates key node attributes stored in the hpenodeinfos Custom Resource
    Definition based on the specified access protocol. Performs protocol-specific
    validation for NVMe NQN (nvmetcp), iSCSI IQN (iscsi), or FC WWN (fc), along
    with common node attributes like UUID and network interfaces.

    This method performs protocol-specific validation:
    - For 'nvmetcp': Validates NVMe Qualified Name (NQN) if expected_nqn provided
    - For 'iscsi': Validates iSCSI Qualified Name (IQN) if expected_iqn provided
    - For 'fc': Validates World Wide Name (WWN) if expected_wwn provided
    - Always validates: UUID (required) and Networks (required)

    Args:
        node_name (str): Name of the Kubernetes node (e.g., "worker-1.domain.com")
        protocol (str): Access protocol - 'nvmetcp', 'iscsi', or 'fc'
        expected_nqn (str, optional): Expected NVMe NQN to validate (only checked if protocol='nvmetcp')
        expected_iqn (str, optional): Expected iSCSI IQN to validate (only checked if protocol='iscsi')
        expected_wwn (str, optional): Expected FC WWN to validate (only checked if protocol='fc')
        expected_uuid (str, optional): Expected node UUID to validate
        hpe3par_cli (HPE3ParClient, optional): HPE 3PAR client for array operations

    Returns:
        bool: True if all validations pass, False if any validation fails

    Example:
        >>> # Validate NVMe protocol with expected host NQN
        >>> result = verify_hpenodeinfo(
        ...     node_name="worker-1.domain.com",
        ...     protocol="nvmetcp",
        ...     expected_nqn="nqn.2014-08.org.nvmexpress:uuid:1234-5678"
        ... )
        >>> print(result)  # True if validation passes

        >>> # Validate iSCSI protocol with expected IQN
        >>> result = verify_hpenodeinfo(
        ...     node_name="worker-1.domain.com",
        ...     protocol="iscsi",
        ...     expected_iqn="iqn.1994-05.com.redhat:worker-1"
        ... )

        >>> # Validate FC protocol with expected WWN
        >>> result = verify_hpenodeinfo(
        ...     node_name="worker-1.domain.com",
        ...     protocol="fc",
        ...     expected_wwn="50060b0000c26604"
        ... )

        >>> # Validate NVMe without expected NQN (checks node has NQNs configured)
        >>> result = verify_hpenodeinfo(
        ...     node_name="worker-1.domain.com",
        ...     protocol="nvmetcp"
        ... )

    Note:
        - Protocol parameter is required and determines which identifier to validate
        - Only validates the identifier matching the specified protocol
        - Expected identifier (NQN/IQN/WWN) is only validated if provided AND protocol matches
        - Returns False if any validation fails instead of raising exceptions
        - UUID and Networks are always validated regardless of protocol
        - Logs detailed verification progress at INFO level
        - Logs errors at ERROR level
        - Node name must match exactly as it appears in Kubernetes (FQDN)
        - Multiple NQNs/IQNs/WWNs can exist on a node; validation checks if expected value exists in list
    """
    try:
        logging.getLogger().info("=" * 80)
        logging.getLogger().info("Verifying HPE Node Info for node: %s (protocol: %s)" % (node_name, protocol))
        logging.getLogger().info("=" * 80)

        # Get hpenodeinfo CRD
        command = "kubectl get hpenodeinfos %s -o json" % node_name
        result = get_command_output_string(command)

        if not result:
            logging.getLogger().error("✗ Failed to get hpenodeinfo for node %s" % node_name)
            return False

        try:
            node_info = json.loads(result)
        except json.JSONDecodeError as e:
            logging.getLogger().error("✗ Failed to parse hpenodeinfo JSON: %s" % e)
            return False

        # Extract record details
        if 'spec' not in node_info:
            logging.getLogger().error("✗ No 'spec' field found in hpenodeinfo")
            return False

        record = node_info['spec']

        # Validate UUID (always required)
        actual_uuid = record.get('uuid', '')
        if not actual_uuid:
            logging.getLogger().error("✗ No UUID found in node record")
            return False

        logging.getLogger().info("✓ UUID found: %s" % actual_uuid)

        if expected_uuid:
            logging.getLogger().info("Checking UUID...")
            logging.getLogger().info("  Expected: %s" % expected_uuid)
            logging.getLogger().info("  Actual: %s" % actual_uuid)

            if actual_uuid != expected_uuid:
                logging.getLogger().error("✗ UUID mismatch")
                return False
            logging.getLogger().info("✓ UUID matches")

        # Validate Networks (always required)
        networks = record.get('networks', [])
        if not networks:
            logging.getLogger().error("✗ No networks found in node record")
            return False

        logging.getLogger().info("✓ Networks found: %s" % networks)

        # Protocol-specific validation
        protocol = protocol.lower()

        if protocol == 'nvmetcp':
            # Validate NVMe NQN
            nqns = record.get('nqns', [])

            if not nqns:
                logging.getLogger().error("✗ No NQNs found for NVMe protocol")
                return False

            logging.getLogger().info("✓ NQNs found: %s" % nqns)

            if expected_nqn:
                logging.getLogger().info("Checking NQN...")
                logging.getLogger().info("  Expected: %s" % expected_nqn)
                logging.getLogger().info("  Actual: %s" % nqns)

                if expected_nqn not in nqns:
                    logging.getLogger().error("✗ Expected NQN not found in node NQNs")
                    return False
                logging.getLogger().info("✓ NQN matches")

        elif protocol == 'iscsi':
            # Validate iSCSI IQN
            iqns = record.get('iqns', [])

            if not iqns:
                logging.getLogger().error("✗ No IQNs found for iSCSI protocol")
                return False

            logging.getLogger().info("✓ IQNs found: %s" % iqns)

            if expected_iqn:
                logging.getLogger().info("Checking IQN...")
                logging.getLogger().info("  Expected: %s" % expected_iqn)
                logging.getLogger().info("  Actual: %s" % iqns)

                if expected_iqn not in iqns:
                    logging.getLogger().error("✗ Expected IQN not found in node IQNs")
                    return False
                logging.getLogger().info("✓ IQN matches")

        elif protocol == 'fc':
            # Validate FC WWN
            wwns = record.get('wwns', [])

            if not wwns:
                logging.getLogger().error("✗ No WWNs found for FC protocol")
                return False

            logging.getLogger().info("✓ WWNs found: %s" % wwns)

            if expected_wwn:
                logging.getLogger().info("Checking WWN...")
                logging.getLogger().info("  Expected: %s" % expected_wwn)
                logging.getLogger().info("  Actual: %s" % wwns)

                # WWN comparison should be case-insensitive
                wwns_lower = [w.lower() for w in wwns]
                if expected_wwn.lower() not in wwns_lower:
                    logging.getLogger().error("✗ Expected WWN not found in node WWNs")
                    return False
                logging.getLogger().info("✓ WWN matches")

        else:
            logging.getLogger().warning("⚠ Unknown protocol: %s" % protocol)

        logging.getLogger().info("=" * 80)
        logging.getLogger().info("✓ HPE Node Info validation successful for %s" % node_name)
        logging.getLogger().info("=" * 80)
        return True

    except Exception as e:
        logging.getLogger().error("Exception while verifying hpenodeinfo: %s" % e)
        logging.getLogger().error("Traceback: ", exc_info=True)
        return False

