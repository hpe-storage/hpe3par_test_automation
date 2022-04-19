import pytest
from time import sleep
import hpe_3par_kubernetes_manager as manager
import logging
import globals

timeout = globals.status_check_timeout

"""logfile = "CSI_test_automation.log"
loglevel = logging.DEBUG
logging.basicConfig(filename=logfile, level=loglevel, format='%(levelname)s-%(asctime)s\n%(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
logging.info('=============================== Test Automation START ========================')
"""


def test_thin_absent_comp_new():
    pvc_create_verify("%s/thin-absent-comp.yml" % globals.yaml_dir)


def test_thin_true_comp_new():
    pvc_create_verify("%s/thin-true-comp.yml" % globals.yaml_dir)


def test_thin_false_comp_new():
    pvc_create_verify("%s/thin-false-comp.yml" % globals.yaml_dir)


def test_thin_blank_comp_new():
    pvc_create_verify("%s/thin-absent-comp.yml" % globals.yaml_dir)


def test_full_absent_comp_new():
    pvc_create_verify("%s/full-absent-comp.yml" % globals.yaml_dir)


def test_full_true_comp_new():
    pvc_create_verify("%s/full-true-comp.yml" % globals.yaml_dir)


def test_full_false_comp():
    pvc_create_verify("%s/full-false-comp.yml" % globals.yaml_dir)


def test_full_blank_comp():
    pvc_create_verify("%s/full-absent-comp.yml" % globals.yaml_dir)


def test_dedup_absent_comp_new():
    if globals.hpe3par_version[0:2] == '4.' or globals.hpe3par_version[0:2] == '9.':
        pvc_create_verify("%s/reduce-absent-comp_primera.yml" % globals.yaml_dir)
    else:
        pvc_create_verify("%s/dedup-absent-comp_3par.yml" % globals.yaml_dir)


def test_dedup_true_comp_new():
    if globals.hpe3par_version[0:2] == '4.' or globals.hpe3par_version[0:2] == '9.':
        pvc_create_verify("%s/reduce-true-comp_primera.yml" % globals.yaml_dir)
    else:
        pvc_create_verify("%s/dedup-true-comp_3par.yml" % globals.yaml_dir)


def test_dedup_false_comp():
    if globals.hpe3par_version[0:2] == '4.' or globals.hpe3par_version[0:2] == '9.':
        pvc_create_verify("%s/reduce-false-comp_primera.yml" % globals.yaml_dir)
    else:
        pvc_create_verify("%s/dedup-false-comp_3par.yml" % globals.yaml_dir)


def test_dedup_blank_comp():
    if globals.hpe3par_version[0:2] == '4.' or globals.hpe3par_version[0:2] == '9.':
        pvc_create_verify("%s/reduce-blank-comp_primera.yml" % globals.yaml_dir)
    else:
        pvc_create_verify("%s/dedup-blank-comp_3par.yml" % globals.yaml_dir)


def test_publish_sanity():
    sc = None
    pvc = None
    pod = None
    try:
        yml = "%s/test-publish.yml" % globals.yaml_dir
        #array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        #hpe3par_cli = manager.get_3par_cli_client(yml)
        #hpe3par_version = manager.get_array_version(hpe3par_cli)
        #print("\n########################### test_publish::%s::%s ###########################" %
        #      (protocol, hpe3par_version[0:5]))
        """logging.error("\n########################### test_publish::%s::%s###########################" %
                      (protocol, hpe3par_version))"""
        #secret = manager.create_secret(yml)
        #step = "secret"
        sc = manager.create_sc(yml)
        #step = "sc"
        pvc = manager.create_pvc(yml)
        #step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        #print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        #print("hpe3par_cli object :: %s " % hpe3par_cli)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        """assert manager.verify_volume_properties(volume, provisioning='thin', compression='true') is True, \
            "tpvv no comp volume verification failed"""""

        pod = manager.create_pod(yml)

        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        # Verify crd fpr published status
        assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is True, \
            "PVC CRD %s Published is false after Pod is running" % pvc_obj.spec.volume_name

        hpe3par_vlun = manager.get_3par_vlun(globals.hpe3par_cli,volume_name)
        assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
            "Node for pod received from 3par and cluster do not match"

        iscsi_ips = manager.get_iscsi_ips(globals.hpe3par_cli)

        # Read pvc crd again after pod creation. It will have IQN and LunId.
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name, pvc_crd, hpe3par_vlun)
        assert flag is True, "partition not found"
        logging.getLogger().info("disk_partition received are %s " % disk_partition)

        flag, disk_partition_mod, partition_map = manager.verify_multipath(hpe3par_vlun, disk_partition)
        assert flag is True, "multipath check failed"
        """print("disk_partition after multipath check are %s " % disk_partition)
        print("disk_partition_mod after multipath check are %s " % disk_partition_mod)"""
        logging.getLogger().info("disk_partition after multipath check are %s " % disk_partition)
        logging.getLogger().info("disk_partition_mod after multipath check are %s " % disk_partition_mod)
        assert manager.verify_partition(disk_partition_mod), "partition mismatch"

        assert manager.verify_lsscsi(pod_obj.spec.node_name, disk_partition), "lsscsi verificatio failed"

        assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                              pod.metadata.name
        assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is True, \
            "Pod %s is not deleted yet " % pod.metadata.name

        flag, ip = manager.verify_deleted_partition(iscsi_ips, pod_obj.spec.node_name, hpe3par_vlun, pvc_crd)
        assert flag is True, "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip

        paths = manager.verify_deleted_multipath_entries(pod_obj.spec.node_name, hpe3par_vlun, disk_partition)
        assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

        # partitions = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
        # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
        flag = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
        #print("flag after deleted lsscsi verificatio is %s " % flag)
        logging.getLogger().info("flag after deleted lsscsi verificatio is %s " % flag)
        assert flag, "lsscsi verification failed for vlun deletion"

        # Verify crd for unpublished status
        try:
            assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is False, \
                "PVC CRD %s Published is true after Pod is deleted" % pvc_obj.spec.volume_name
            #print("PVC CRD published is false after pod deletion.")
            logging.getLogger().info("PVC CRD published is false after pod deletion.")
            #logging.warning("PVC CRD published is false after pod deletion.")
        except Exception as e:
            #print("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
            logging.getLogger().warning("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
            #logging.error("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        #pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        #print("PVC crd after PVC object deletion :: %s " % pvc_crd)
        assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name"""

    except Exception as e:
        #print("Exception in test_publish :: %s" % e)
        logging.getLogger().error("Exception in test_publish :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        """if step == 'pvc':
            manager.delete_pvc(pvc.metadata.name)
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'sc':
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'secret':
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
        raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, sc, pvc, pod)


def test_clone_sanity():
    sc = None
    pvc = None
    pod = None
    clone_pvc = None
    try:
        base_yml = "%s/base-pvc-clone.yml" % globals.yaml_dir
        clone_yml = "%s/test-clone.yml" % globals.yaml_dir
        """hpe3par_cli = manager.get_3par_cli_client(base_yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_clone::%s::%s ###########################" %
              (protocol, hpe3par_version[0:5]))"""
        """logging.info("\n########################### test_clone::%s::%s###########################" %
                     (protocol, hpe3par_version))"""
        #secret = manager.create_secret(base_yml)
        #step = "secret"
        sc = manager.create_sc(base_yml)
        step = "sc"
        pvc = manager.create_pvc(base_yml)
        step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        #print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        logging.getLogger().info(globals.hpe3par_cli)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        clone_pvc = manager.create_pvc(clone_yml)
        step = "clone_pvc"
        flag, clone_pvc_obj = manager.check_status(timeout, clone_pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=clone_pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % clone_pvc_obj.metadata.name

        assert manager.verify_clone_crd_status(clone_pvc_obj.spec.volume_name) is True, \
            "Clone PVC CRD is not yet completed"

        """assert manager.verify_volume_properties(volume, provisioning='thin', compression='true') is True, \
            "tpvv no comp volume verification failed"""""
        clone_pvc_crd = manager.get_pvc_crd(clone_pvc_obj.spec.volume_name)
        # print(pvc_crd)
        clone_volume_name = manager.get_pvc_volume(clone_pvc_crd)

        assert manager.delete_pvc(clone_pvc.metadata.name)

        assert manager.check_if_deleted(timeout, clone_pvc.metadata.name, "PVC", namespace=clone_pvc.metadata.namespace)\
               is True, "Clone PVC %s is not deleted yet " % clone_pvc.metadata.name

        assert manager.check_if_crd_deleted(clone_pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
            "Clone PVC CRD %s of %s is not deleted yet. Taking longer..." % (clone_pvc_obj.spec.volume_name, 'hpevolumeinfos')

        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, clone_volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (clone_volume_name, clone_pvc.metadata.name)

        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

        sleep(30)
        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name """

    except Exception as e:
        logging.getLogger().error("Exception in test_clone :: %s" % e)
        #logging.error("Exception in test_clone :: %s" % e)
        """if step == 'pvc':
            manager.delete_pvc(pvc.metadata.name)
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'sc':
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'secret':
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
        raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, None, clone_pvc, None)
        cleanup(None, sc, pvc, None)


def test_snapshot_sanity():
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        base_yml = "%s/source-pvc-snap.yml" % globals.yaml_dir
        """hpe3par_cli = manager.get_3par_cli_client(base_yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_snapshot::%s::%s ###########################" %
              (protocol, hpe3par_version[0:5]))"""
        """logging.info("\n########################### test_clone::%s::%s###########################" %
                     (protocol, hpe3par_version))"""
        """secret = manager.create_secret(base_yml)
        step = "secret"""""
        sc = manager.create_sc(base_yml)
        #step = "sc"
        pvc = manager.create_pvc(base_yml)
        #step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        logging.getLogger().info(globals.hpe3par_cli)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        #assert manager.create_snapclass("%s/snapshot-class.yaml" % globals.yaml_dir) is True, 'Snapclass ci-snapclass is not created.'
        manager.create_snapclass("%s/snapshot-class.yaml" % globals.yaml_dir)

        assert manager.verify_snapclass_created() is True, 'Snapclass ci-snapclass is not found in crd list.'

        #assert manager.create_snapshot("%s/snapshot.yaml" % globals.yaml_dir) is True, 'Snapshot ci-pvc-snapshot is not created.'
        manager.create_snapshot("%s/snapshot.yaml" % globals.yaml_dir)

        assert manager.verify_snapshot_created() is True, 'Snapshot ci-pvc-snapshot is not found in crd list.'

        flag, snap_uid = manager.verify_snapshot_ready()
        assert flag is True, "Snapshot ci-pvc-snapshot is not ready to use"

        snap_uid = "snapshot-" + snap_uid
        snap_volume = manager.get_volume_from_array(globals.hpe3par_cli, snap_uid[0:31])
        snap_volume_name = snap_volume['name']
        logging.getLogger().info("snap_volume :: %s " % snap_volume)
        flag, message = manager.verify_snapshot_on_3par(snap_volume, volume_name)
        assert flag is True, message
        #assert manager.delete_snapshot(), "Snapshot ci-pvc-snapshot deletion request failed"
        manager.delete_snapshot()
        #sleep(180)
        assert manager.check_if_crd_deleted('ci-pvc-snapshot', "volumesnapshots") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % ('ci-pvc-snapshot', 'volumesnapshots')
        #assert manager.verify_snapshot_deleted() is False, 'Snapshot CRD ci-pvc-snapshot is not deleted yet.'
        #sleep(180)
        #assert manager.delete_snapclass(), "Snapclass ci-snapclass deletion request failed"
        manager.delete_snapclass()
        assert manager.check_if_crd_deleted('ci-snapclass', "volumesnapshotclasses") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % ('ci-snapclass', 'volumesnapshotclasses')
        #sleep(180)
        #assert manager.verify_snapclass_deleted is False, 'Snapclass CRD ci-snapclass is not deleted yet.'
        #sleep(180)
        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, snap_volume_name) is True, \
            "Snap Volume %s from 3PAR for PVC %s is not deleted" % (snap_volume_name, pvc.metadata.name)
        
        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret",
                                        namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name"""

    except Exception as e:
        logging.getLogger().error("Exception in test_snapshot :: %s" % e)
        #logging.error("Exception in test_snapshot :: %s" % e)
        """if step == 'pvc':
            manager.delete_pvc(pvc.metadata.name)
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'sc':
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'secret':
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
        raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, sc, pvc, None)
        cleanup_snapshot()


#@pytest.mark.skip(reason="skipped as not implementation yet")
def test_expand_volume_sanity():
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        yml = "%s/test-expand_vol_pvc.yml" % globals.yaml_dir
        """hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_expand_volume::%s::%s ###########################" %
              (protocol, hpe3par_version[0:5]))"""
        """logging.info("\n########################### test_expand_volume::%s::%s###########################" %
                     (protocol, hpe3par_version))"""
        #secret = manager.create_secret(yml)
        #step = "secret"
        sc = manager.create_sc(yml)
        #step = "sc"
        pvc = manager.create_pvc(yml)
        #step = "pvc"
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        logging.getLogger().info("volume_name :: %s " % volume_name)
        logging.getLogger().info(globals.hpe3par_cli)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name
        logging.getLogger().info("Volume verification at array done successfully")
        # patch pvc for expand size
        size_in_gb = '20'
        patch_json = {'spec': {'resources': {'requests': {'storage': size_in_gb + 'Gi'}}}}
        mod_pvc = manager.patch_pvc(pvc.metadata.name, pvc.metadata.namespace, patch_json)
        logging.getLogger().info("Patched PVC %s" % mod_pvc)

        pod = manager.create_pod("%s/test-expand_vol_pod.yml" % globals.yaml_dir)

        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        # Now check if volume in 3par has increased size
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume['sizeMiB'] == int(size_in_gb) * 1024, "Volume on array does not have updated size"

        # Check if PVC has increaded size
        mod_pvc = manager.hpe_read_pvc_object(pvc.metadata.name, pvc.metadata.namespace)
        logging.getLogger().info("PVC after expansion %s" % mod_pvc)
        # assert mod_pvc['spec']['resources']['requests']['storage'] == "%sGi" % size_in_gb, "PVC %s does not have updated size" % pvc.metadata.name
        assert mod_pvc.spec.resources.requests['storage'] == "%sGi" % size_in_gb, "PVC %s does not have updated size" % pvc.metadata.name

        # check size of mounted vlun
        """node = pod_obj.spec.node_name
        hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli,volume_name)
        vv_wwn = hpe3par_vlun['volumeWWN']

        command = "mount | grep -i 3%s" % vv_wwn"""
        assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                              pod.metadata.name
        assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is True, \
            "Pod %s is not deleted yet " % pod.metadata.name

        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

        assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret",
                                        namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name"""

    except Exception as e:
            logging.getLogger().error("Exception in test_expand_volume :: %s" % e)
            #logging.error("Exception in test_snapshot :: %s" % e)
            """if step == 'pvc':
                manager.delete_pvc(pvc.metadata.name)
                manager.delete_sc(sc.metadata.name)
                manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
            if step == 'sc':
                manager.delete_sc(sc.metadata.name)
                manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
            if step == 'secret':
                manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
            raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, sc, pvc, pod)


def cleanup_snapshot():
    if manager.verify_snapshot_deleted() is False:
        manager.delete_snapshot()
    if manager.verify_snapclass_deleted is False:
        manager.delete_snapclass()


def cleanup(secret, sc, pvc, pod):
    #print("====== cleanup :START =========")
    logging.getLogger().info("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", namespace=sc.metadata.namespace) is False:
        manager.delete_sc(sc.metadata.name)
    """if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is False:
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
    #print("====== cleanup :END =========")
    logging.getLogger().info("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")


def pvc_create_verify(yml):
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        """array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_cli = manager.get_3par_cli_client(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### new_method %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))"""
        #logging.info("\n########################### test_thin_absent_comp::%s::%s###########################" %
                     #(protocol, hpe3par_version))
        #secret = manager.create_secret(yml)
        #step = "secret"
        sc = manager.create_sc(yml)
        #step = "sc"
        pvc = manager.create_pvc(yml)

        #step = "pvc"
        # Check PVC status in events
        provisioning = None
        compression = None
        size = None
        is_cpg_ssd = None
        provisioning, compression, cpg_name, size = manager.get_sc_properties(yml)
        logging.getLogger().info("Check if cpg is ssd")
        is_cpg_ssd = manager.check_cpg_prop_at_array(globals.hpe3par_cli, cpg_name, property='ssd')
        logging.getLogger().info("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        logging.getLogger().info("Check if test passed...")
        flag = manager.is_test_passed(array_version=globals.hpe3par_version, status=status, is_cpg_ssd=is_cpg_ssd,
                                      provisioning=provisioning, compression=compression)
        logging.getLogger().info("Test passed :: %s " % flag)
        assert flag is True, message
                                                                                           

        if status == 'ProvisioningSucceeded':
            flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
            assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

            pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
            #print(pvc_crd)
            volume_name = manager.get_pvc_volume(pvc_crd)
            logging.getLogger().info(globals.hpe3par_cli)
            volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
            assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name
            logging.getLogger().info(volume)
            flag, failure_cause = manager.verify_volume_properties_3par(volume, size=size, provisioning=provisioning,
                                                                        compression=compression, cpg=cpg_name)
            assert flag is True, "Volume properties verification at array is failed for %s" % failure_cause

        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        if status == 'ProvisioningSucceeded':
            assert manager.check_if_crd_deleted(pvc_obj.spec.volume_name, "hpevolumeinfos") is True, \
                "CRD %s of %s is not deleted yet. Taking longer..." % (pvc_obj.spec.volume_name, 'hpevolumeinfos')

            assert manager.verify_delete_volume_on_3par(globals.hpe3par_cli, volume_name), \
                "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        """assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name"""

    except Exception as e:
        logging.getLogger().error("Exception in pvc_create_verify :: %s" % e)
        #logging.error("Exception in test_thin_absent :: %s" % e)
        """if step == 'pvc':
            manager.delete_pvc(pvc.metadata.name)
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'sc':
            manager.delete_sc(sc.metadata.name)
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        if step == 'secret':
            manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
        raise e

    finally:
        #hpe3par_cli.logout()
        cleanup(None, sc, pvc, None)
#logging.info('=============================== Test Automation END ========================')
