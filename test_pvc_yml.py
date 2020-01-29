import hpe_3par_kubernetes_manager as manager
import yaml
from time import sleep
import base64
import pytest

objects = {}
timeout = 180
HPE3PAR_IP = None
HPE3PAR_USERNAME = None
HPE3PAR_PWD = None
HPE3PAR_API_URL = None

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
        print("Sleeping for 30 seconds...")
        sleep(30)
        print("Resume")
        PVC = manager.hpe_read_pvc_object(objects['PVC'])
        assert PVC.status.phase == 'Bound', 'PVC %s is not in Bound state ' % objects['PVC']
        print("PVC %s is in Bound state" % objects['PVC'])
        objects["PVC_Volume_name"] = str(PVC.spec.volume_name)[0:31]
    except Exception as e:
        print("Exception while verifying pvc status :: %s" % e)
        raise e


def test_verify_on_3par():
    try:
        global HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, HPE3PAR_API_URL
        HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD = manager.read_array_prop("YAML/test-pvc.yml")
        HPE3PAR_API_URL = "https://" + HPE3PAR_IP + ":8080/api/v1"
        """ print("HPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                      HPE3PAR_IP,
                                                                                                      HPE3PAR_USERNAME,
                                                                                                      base64.decodestring(HPE3PAR_PWD)))"""

        hpe3par_cli = manager._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                         HPE3PAR_USERNAME, base64.decodestring(HPE3PAR_PWD))
        hpe3par_volume = hpe3par_cli.getVolume(objects["PVC_Volume_name"])
        hpe3par_cli.logout()
        assert hpe3par_volume is not None, "Volume is not created on 3PAR for pvc %s " % objects['PVC']
        print("\n Volume is created successfully on 3PAR for PVC %s " % objects['PVC'])
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e


def test_delete_and_verify_objects():
    print("\n########################### test_delete_objects ###########################")
    sleep(120)
    try:
        # Delete objects and verify
        for kind, name in objects.items():
            print(kind, ":", name)
            if kind == "Secret":
                print("Deleting Secret %s..." % name)
                manager.hpe_delete_secret_object_by_name(name)

                assert manager.check_if_deleted(timeout, name, "Secret") is True, "Secret %s is not deleted yet " % name
                print("Secret %s is deleted." % name)
            if kind == "PVC":
                print("Deleting PVC %s..." % name)
                manager.hpe_delete_pvc_object_by_name(name)

                assert manager.check_if_deleted(timeout, name, "PVC") is True, "PVC %s is not deleted yet " % name
                print("PVC %s is deleted." % name)
            if kind == "SC":
                print("Deleting SC %s..." % name)
                manager.hpe_delete_sc_object_by_name(name)

                assert manager.check_if_deleted(timeout, name, "SC") is True, "SC %s is not deleted yet " % name
                print("SC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting objects :: %s" % e)
        raise e


@pytest.mark.skip(reason="skipped as bug is raised")
def test_verify_delete_on_3par():
    try:
        """ print("HPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                      HPE3PAR_IP,
                                                                                                      HPE3PAR_USERNAME,
                                                                                                      base64.decodestring(HPE3PAR_PWD)))"""

        hpe3par_cli = manager._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                         HPE3PAR_USERNAME, base64.decodestring(HPE3PAR_PWD))
        hpe3par_volume = hpe3par_cli.getVolume(objects["PVC_Volume_name"])
        hpe3par_cli.logout()
        assert hpe3par_volume is None, "Volume is not deleted from 3PAR after deleting of pvc %s " % objects['PVC']
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e
