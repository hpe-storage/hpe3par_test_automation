import hpe_3par_kubernetes_manager as manager
import test_helm_install_uninstall as tc
import time
import yaml
import base64
import logging
import globals

globals.newbrand_test = False

def test_alletra_svc_alletra_backend():
    verify_new_brand("%s/new_branding/alletra-svc-alletra-backend-secret.yaml" % globals.yaml_dir)


def test_alletra_svc_3par_backend():
    verify_new_brand("%s/new_branding/alletra-svc-3par-backend-secret.yaml" % globals.yaml_dir)


def test_alletra_svc_primera_backend():
    verify_new_brand("%s/new_branding/alletra-svc-primera-backend-secret.yaml" % globals.yaml_dir)


def test_primera3par_svc_alletra_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-alletra-backend-secret.yaml" % globals.yaml_dir)



def test_primera3par_svc_3par_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-3par-backend-secret.yaml" % globals.yaml_dir)



def test_primera3par_svc_primera_backend():
    verify_new_brand("%s/new_branding/primera3par-svc-primera-backend-secret.yaml" % globals.yaml_dir)



def verify_new_brand(yml):
    global my_hpe3par_cli
    #secret_yaml = '%s/new_branding//alletra-svc-3par-backend-secret.yaml' % globals.yaml_dir
    sc_yml = '%s/new_branding//sc.yaml' % globals.yaml_dir
    pvc_yml = '%s/new_branding//pvc.yaml' % globals.yaml_dir
    pod_yml = '%s/new_branding//pod.yaml' % globals.yaml_dir
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
        logging.getLogger().info("globals.hpe3par_cli object :: %s " % globals.hpe3par_cli)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        pod = manager.create_pod(pod_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name


    finally:
        # Now cleanup sc, pv, pvc, pod
        #print("Inside Finally")
        cleanup(secret, sc, pvc, pod)


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
