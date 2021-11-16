import hpe_3par_kubernetes_manager as manager
#import test_helm_install_uninstall as tc
import time
import yaml
import base64
import logging
import globals

globals.newbrand_test = False

def test_alletra_svc_alletra_backend_sanity():
    verify_new_brand("%s/new_branding/alletra-svc-alletra-backend-secret.yaml" % globals.yaml_dir)


def test_alletra_svc_3par_backend():
    verify_new_brand("%s/new_branding/alletra-svc-3par-backend-secret.yaml" % globals.yaml_dir)


def test_alletra_svc_primera_backend():
    verify_new_brand("%s/new_branding/alletra-svc-primera-backend-secret.yaml" % globals.yaml_dir)


def test_primera3par_svc_alletra_backend_sanity():
    verify_new_brand("%s/new_branding/primera3par-svc-alletra-backend-secret.yaml" % globals.yaml_dir)



def test_primera3par_svc_3par_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-3par-backend-secret.yaml" % globals.yaml_dir)



def test_primera3par_svc_primera_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-primera-backend-secret.yaml" % globals.yaml_dir)


def test_primera3par_svc_primera_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-primera-backend-secret.yaml" % globals.yaml_dir)


def test_primera3par_and_alletra_svc_primera_alletra_backend():
    pod_list =[]
    pvc_list =[]
    sc_list =[]
    secret_list =[]
    yml_list =[ "%s/new_branding/multiple_service_pod_alletra.yaml" % globals.yaml_dir, "%s/new_branding/multiple_service_pod_primera.yaml" % globals.yaml_dir]
    try: 
        for yml in yml_list:
            secret_list,sc_list,pvc_list,pod_list = verify_multiple_service_pod(yml, pod_list, pvc_list, sc_list, secret_list)

        for pod in pod_list:
            cleanup(None, None, None, pod)
        for pvc in pvc_list:
            cleanup(None, None, pvc, None)
        for sc in sc_list:
            cleanup(None, sc, None, None)
        for secret in secret_list:
            cleanup(secret, None, None, None)
    finally:
        print("Inside finally")
        if not pod_list:
            for pod in pod_list:
                cleanup(None, None, None, pod)
        if not pvc_list:
            for pvc in pvc_list:
                cleanup(None, None, pvc, None)
        if not sc_list:
            for sc in sc_list:
                cleanup(None, sc, None, None)
        if not secret_list:
            for secret in secret_list:
                cleanup(secret, None, None, None)

def verify_new_brand(yml):
    global my_hpe3par_cli
    #secret_yaml = '%s/new_branding//alletra-svc-3par-backend-secret.yaml' % globals.yaml_dir
    sc_yml = '%s/new_branding//sc.yaml' % globals.yaml_dir
    pvc_yml = '%s/new_branding//pvc.yaml' % globals.yaml_dir
    pod_yml = '%s/new_branding//pod.yaml' % globals.yaml_dir
    with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            logging.getLogger().debug(elements)
            for el in elements:
                if str(el.get('kind')) == "Secret":
                    HPE3PAR_IP = el['stringData']['backend']
                break
    secret = None
    sc = None
    pvc = None
    pod = None
    namespace = globals.namespace
    timeout = globals.status_check_timeout

    try:
        # Create secret sc, pvc, pod
        secret = manager.create_secret(yml, namespace)
        sc = manager.create_sc(sc_yml)
        step = "sc"
        pvc = manager.create_pvc(pvc_yml)
        step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        hpe3par_cli = manager.get_3par_cli_client(HPE3PAR_IP)
        volume = manager.get_volume_from_array(hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        pod = manager.create_pod(pod_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name


    finally:
        # Now cleanup sc, pv, pvc, pod
        #print("Inside Finally")
        cleanup(secret, sc, pvc, pod)


def verify_multiple_service_pod(yml, pod_list, pvc_list, sc_list, secret_list):
    with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            logging.getLogger().debug(elements)
            for el in elements:
                if str(el.get('kind')) == "Secret":
                    HPE3PAR_IP = el['stringData']['backend']
                break
    secret = None
    sc = None
    pvc = None
    pod = None
    namespace = globals.namespace
    timeout = globals.status_check_timeout

    try:
        # Create secret sc, pvc, pod
        secret = manager.create_secret(yml, namespace)
        secret_list.append(secret)
        sc = manager.create_sc(yml)
        sc_list.append(sc)
        step = "sc"
        pvc = manager.create_pvc(yml)
        pvc_list.append(pvc)
        step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        hpe3par_cli = manager.get_3par_cli_client(HPE3PAR_IP)
        volume = manager.get_volume_from_array(hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        pod = manager.create_pod(yml)
        pod_list.append(pod)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_multiple_service_pod :: %s" % e)
        raise e

    finally:
       return secret_list, sc_list, pvc_list, pod_list


def cleanup(secret, sc, pvc, pod):
    logging.getLogger().info("====== cleanup :START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", None) is False:
        manager.delete_sc(sc.metadata.name)
    if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "SECRET", None) is False:
        manager.delete_secret(secret.metadata.name,globals.namespace)
    logging.getLogger().info("====== cleanup :END =========")
