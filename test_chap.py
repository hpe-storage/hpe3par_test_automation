import hpe_3par_kubernetes_manager as manager
import test_helm_install_uninstall as tc
import time
import yaml
import base64
from hpe3parclient.exceptions import HTTPBadRequest
from hpe3parclient.exceptions import HTTPForbidden
from hpe3parclient.exceptions import HTTPConflict
from hpe3parclient.exceptions import HTTPNotFound


def test_chap():
    sc_yml = 'YAML/YAML_CHAP/sc_140.yaml'
    pvc_yml = 'YAML/YAML_CHAP/pvc_140.yaml'
    pod_yml = 'YAML/YAML_CHAP/pod_140.yml'
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    timeout = 900
    
    # Fetching chap details from install yml
    with open("INSTALL/values.yaml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)

    chapUsr = cfg['iscsi']['chapUser']
    chapPwd = cfg['iscsi']['chapPassword']
    try:
        yml = "YAML/YAML_CHAP/sc_140.yaml"
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_cli = manager.get_3par_cli_client(yml)

        hpe3par_version = manager.get_array_version(hpe3par_cli)

        # Call uninstall of plugin, to re-install the product with chap enabled
        tc.test_helm_uninstall()
        time.sleep(20)

        # Call install with CHAP enabled 
        tc.test_helm_install()


        # Get node details.
        node_list = manager.hpe_list_node_objects()
        workers = {}
        for _ in node_list.items:
            if 'worker_id' in _.metadata.labels:
                workers[ _.metadata.name] = _.status.addresses[0].address
            else:
                continue

        # Validate node crd
        worker_node_name = [ keys for keys in workers]
        for node_name in worker_node_name:
            flag = manager.verify_node_crd_chap(node_name,chapUser=chapUsr,chapPassword=chapPwd)
        assert flag is True, "Crd validation failed"

        # Create sc, pvc, pod
        secret = manager.create_secret(sc_yml)
        step = "secret"
        sc = manager.create_sc(sc_yml)
        step = "sc"
        pvc = manager.create_pvc(pvc_yml)
        step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        #print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        print("hpe3par_cli object :: %s " % hpe3par_cli)
        volume = manager.get_volume_from_array(hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        pod = manager.create_pod(pod_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        
        #Validate chap details on 3par
        host_name = (pod_obj.spec.node_name).split(".")[0]
        host_ip = pod_obj.status.host_ip
        hpe3par_host = manager.get_host_from_array(hpe3par_cli, host_name)
        flag = manager.verify_host_properties(hpe3par_host, chapUser=chapUsr,chapPassword=chapPwd)
        assert flag is True, "Verification of crd on array failed" 
        
        #Validate chap details on host. 
        command = "iscsiadm -m node -o show | grep -w node.session.auth.username"
        raw_output = manager.get_command_output(host_name,command) 
        assert raw_output[0].split(",")[0].split("=")[1].strip() == chapUsr, "Chap user not as in input file %s " % raw_output[0].split(",")[0].split("=")[1]
        command = "iscsiadm -m node -o show | grep -w node.session.auth.password"
        raw_output = manager.get_command_output(host_name,command)
        assert raw_output[0].split(",")[0].split("=")[1], "Chap password on host is 'NULL' %s " % raw_output[0].split(",")[0].split("=")[1]
        
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        print("Inside Finally")
        cleanup(secret, sc, pvc, pod)
        hpe3par_cli.logout()


def cleanup(secret, sc, pvc, pod):
    print("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC") is False:
        manager.delete_sc(sc.metadata.name)
    if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is False:
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
    print("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")

