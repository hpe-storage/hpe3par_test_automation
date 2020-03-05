import hpe_3par_kubernetes_manager as manager
import yaml
from time import sleep
import base64
import pytest

encoding = "utf-8"
objects = {}
timeout = 180
HPE3PAR_IP = None
HPE3PAR_USERNAME = None
HPE3PAR_PWD = None
HPE3PAR_API_URL = None

hpe3par_cli = None


def test_create_objects():
    print("\n########################### test_create_objects ###########################")
    try:
        # Create PV, PVC and Pod
        yml = "YAML//base-pvc-clone.yml"
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
                    secret_obj = manager.hpe_create_secret_object(el)
                    secret_name = secret_obj.metadata.name
                    print("\nSecret %s created." % secret_name)
                    secret_map = {'name': str(secret_name), 'namespace': secret_obj.metadata.namespace}
                    objects["Secret"] = secret_map
    except Exception as e:
        print("Exception while creating objects :: %s" % e)
        raise e


def test_verify_pvc():
    print("\n########################### test_verify_pvc ###########################")
    try:
        print("Waiting for PVC %s to come in Bound state..." % objects['PVC'])
        flag, pvc_obj = manager.check_status(timeout, objects['PVC'], kind='pvc', status='Bound')
        if flag is True:
            assert flag is True, \
                "Persistent Volume %s status check timed out, not in Bound state yet..." % objects['PVC']
        print("\nPVC %s is in Bound state" % objects['PVC'])
        objects['PVC_Volume_name'] = str(pvc_obj.spec.volume_name)[0:31]
    except Exception as e:
        print("Exception while verifying pvc status :: %s" % e)
        raise e


def test_verify_on_3par():
    print("\n########################### test_verify_on_3par ###########################")
    try:
        global HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, HPE3PAR_API_URL
        global hpe3par_cli
        HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD = manager.read_array_prop("YAML/base-pvc-clone.yml")
        HPE3PAR_API_URL = "https://" + HPE3PAR_IP + ":8080/api/v1"
        print("HPE3PAR_API_URL :: %s, HPE3PAR_IP :: %s, HPE3PAR_USERNAME :: %s, HPE3PAR_PWD :: %s" % (HPE3PAR_API_URL,
                                                                                                      HPE3PAR_IP,
                                                                                                      HPE3PAR_USERNAME,
                                                                                                      (base64.b64decode(HPE3PAR_PWD)).decode(encoding)))

        hpe3par_cli = manager._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                         HPE3PAR_USERNAME, (base64.b64decode(HPE3PAR_PWD)).decode(encoding))
        hpe3par_volume = hpe3par_cli.getVolume(objects["PVC_Volume_name"])
        hpe3par_cli.logout()
        assert hpe3par_volume is not None, "Volume is not created on 3PAR for pvc %s " % objects['PVC']
        print("\n Volume is created successfully on 3PAR for PVC %s " % objects['PVC'])
    except Exception as e:
        print("Exception while verifying on 3par :: %s" % e)
        raise e


def test_create_clone_pvc():
    print("\n########################### test_create_clone_pvc ###########################")
    try:
        yml = "YAML/test-clone.yml"
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) == "PersistentVolumeClaim":
                    print("\nCreating PVC...")
                    pvc_name = manager.hpe_create_pvc_object(el).metadata.name
                    print("\nPersistentVolumeClaim %s created." % pvc_name)
                    objects["PVC-clone"] = str(pvc_name)
        sleep(10)
        PVC = manager.hpe_read_pvc_object(objects['PVC'])
        assert PVC is not None, 'Clone PVC %s is not created.' % objects["PVC-clone"]
    except Exception as e:
        print("Exception while creating clone pvc :: %s" % e)
        raise e
    # Now verify if it comes to Bound
    try:
        print("Waiting for PVC %s to come in Bound state..." % objects['PVC-clone'])
        flag, pvc_obj = manager.check_status(timeout, objects['PVC-clone'], kind='pvc', status='Bound')
        if flag is True:
            assert flag is True, \
                "Persistent Volume %s status check timed out, not in Bound state yet..." % objects['PVC-clone']
        objects['PVC-clone_Volume_name'] = str(pvc_obj.spec.volume_name)[0:31]
        assert PVC.status.phase == 'Bound', 'Clone PVC %s is not in Bound state ' % objects['PVC-clone']
        print("Clone PVC %s is in Bound state" % objects['PVC-clone'])
    except Exception as e:
        print("Exception while verifying clone pvc Bound status :: %s" % e)
        raise e


@pytest.mark.skip(reason="skipped as not implementation yet")
def test_verify_pvc_properties():
    print("\n########################### test_create_clone_pvc ###########################")
    # to be implemented


def test_delete_clone():
    print("\n########################### test_delete_clone ###########################")
    try:
        name = objects["PVC-clone"]
        print("Deleting clone PVC %s..." % name)
        manager.hpe_delete_pvc_object_by_name(name)

        assert manager.check_if_deleted(timeout, name, "PVC") is True, "Clone PVC %s is not deleted yet " % name
        print("Clone PVC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting clone pvc :: %s" % e)
        raise e


def test_delete_base_pvc():
    print("\n########################### test_delete_base_pvc ###########################")
    try:
        name = objects["PVC"]
        print("Deleting PVC %s..." % name)
        manager.hpe_delete_pvc_object_by_name(name)

        assert manager.check_if_deleted(timeout, name, "PVC") is True, "PVC %s is not deleted yet " % name
        print("PVC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting base pvc :: %s" % e)
        raise e


def test_delete_sc():
    print("\n########################### test_delete_sc ###########################")
    try:
        name = objects["SC"]
        print("Deleting SC %s..." % name)
        manager.hpe_delete_sc_object_by_name(name)

        assert manager.check_if_deleted(timeout, name, "SC") is True, "SC %s is not deleted yet " % name
        print("SC %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting storage class :: %s" % e)
        raise e


def test_delete_secret():
    print("\n########################### test_delete_secret ###########################")
    try:
        name = objects["Secret"]['name']
        namespace = objects["Secret"]['namespace']
        print("Deleting Secret %s..." % name)
        manager.hpe_delete_secret_object_by_name(name, namespace=namespace)

        assert manager.check_if_deleted(timeout, name, "Secret", namespace=namespace) is True, \
            "Secret %s is not deleted yet " % name
        print("Secret %s is deleted." % name)
    except Exception as e:
        print("Exception while deleting secret :: %s" % e)
        raise e


def test_verify_delete_clone_pvc_on_3par():
    try:
        hpe3par_volume = hpe3par_cli.getVolume(objects["PVC-clone_Volume_name"])
        assert hpe3par_volume is None, "Clone Volume is not deleted from 3PAR after deleting of clone pvc %s " % objects['PVC-clone']
    except Exception as e:
        print("Exception while verifying clone volume deletion on 3par :: %s" % e)
        raise e


def test_verify_delete_base_pvc_on_3par():
    try:
        hpe3par_volume = hpe3par_cli.getVolume(objects["PVC_Volume_name"])
        hpe3par_cli.logout()
        assert hpe3par_volume is None, "Volume is not deleted from 3PAR after deleting of base pvc %s " % objects['PVC']
    except Exception as e:
        print("Exception while verifying base volume deletion on 3par :: %s" % e)
        raise e

