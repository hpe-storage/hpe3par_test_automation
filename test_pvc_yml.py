import hpe_3par_kubernetes_manager as manager
import yaml
from time import sleep

objects = {}

def test_create_objects():
    print("\n########################### test_create_objects ###########################")
    try:
        # Create PV, PVC and Pod
        yml = "YAML/test-pvc.yml"
        global pv_name, pvc_name, pod_name, pod_node_name
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    # print("PersistentVolume YAML :: %s" % el)
                    print("\nCreating StorageClass...")
                    sc_name = manager.hpe_create_sc_object(el).metadata.name
                    print("\nStorageClass %s created." % sc_name)
                    objects["SC"] = str(sc_name)
                if str(el.get('kind')) == "PersistentVolumeClaim":
                    print("\nCreating PVC...")
                    pvc_name = manager.hpe_create_pvc_object(el).metadata.name
                    print("\nPersistentVolumeClaim %s created." % pvc_name)
                    objects["PVC"] = str(pvc_name)
                if str(el.get('kind')) == "Secret":
                    print("\nCreating Secret...")
                    secret_name = manager.hpe_create_secret_object(el).metadata.name
                    print("\nSecret %s created." % secret_name)
                    objects["Secret"] = str(secret_name)
    except Exception as e:
        print("Exception while creating objects :: %s" % e)
        raise e


def test_verify_pvc():
    print("\n########################### test_verify_pvc ###########################")
    try:
        print("Sleeping...")
        sleep(60)
        print("Resume")
        PVC = manager.hpe_read_pvc_object(objects['PVC'])
        assert PVC.status.phase == 'Bound', 'PVC %s is not in Bound state ' % objects['PVC']
    except Exception as e:
        print("Exception while verifying pvc status :: %s" % e)
        raise e


#def test_verify_on_3par():
#    try:
#        hpe3par_cli = manager._hpe_get_3par_client_login(array_conf.HPE3PAR_API_URL, array_conf.HPE3PAR_IP,
#                                                         array_conf.HPE3PAR_USERNAME, array_conf.HPE3PAR_PWD)
#        hpe3par_volume = hpe3par_cli.getVolume(backend_volume_name)
#        hpe3par_cli.logout()
#    except Exception as e:
#        print("Exception while verifying on 3par :: %s" % e)
#        raise e

