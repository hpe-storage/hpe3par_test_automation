import hpe_3par_kubernetes_manager as manager
from hpe3parclient.exceptions import HTTPBadRequest
from hpe3parclient.exceptions import HTTPForbidden
from hpe3parclient.exceptions import HTTPConflict
from hpe3parclient.exceptions import HTTPNotFound

import logging
import globals
from time import sleep

def test_import_vol_as_clone():
    yml = '%s/import_vol/import-vol-as-clone.yml' % globals.yaml_dir
    sc = None
    pvc_obj = None
    pod_obj = None
    vol_name = None
    try:
        # Create volume
        """hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        logging.getLogger().info("\n########################### test_import_cloned_vol test %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))"""

        yaml_values = manager.get_details_for_volume(yml)
        options = prepare_options(yaml_values, globals.hpe3par_version)
        # Create volume in array to be cloned and later imported to csi
        vol_name = yaml_values['vol_name']
        volume = None
        volume, exception = create_vol_in_array(globals.hpe3par_cli, options, vol_name=vol_name, size=yaml_values['size'],
                                                cpg_name=yaml_values['cpg'])
        # assert volume is not None, "Volume %s is not created on array as %s. Terminating test." % (vol_name, exception)
        if volume is None:
            logging.getLogger().info("Volume %s is not created on array as %s. Terminating test." % (vol_name, exception))
            return
        logging.getLogger().info("Volume %s created successfully on array. Now Create clone..." % volume['name'])
        #clone_volume, message = create_clone_in_array(globals.hpe3par_cli, source_vol_name=vol_name, option={'online': True, 'tpvv': True})
        #logging.getLogger().info("Cloned volume is :: %s" % clone_volume)
        #message = "Clone volume creation on array failed with error %s. Terminating test." % message
        #assert clone_volume is not None, message
        #clone_vol_name = clone_volume['name']

        # Now import base of the clone to csi
        #secret = manager.create_secret(yml)
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        logging.getLogger().info("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        assert status == 'ProvisioningSucceeded', f"{message}"
        flag, pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s for base volume %s status check timed out, not in Bound state yet..." % \
                             (pvc_obj.metadata.name, vol_name)
        logging.getLogger().info("\n\nBase volume (after cloning at array) has been imported successfully to CSI.")

        import pdb;pdb.set_trace()
        # Compare imported volume object with old volume object on array
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # logging.getLogger().info(pvc_crd)
        imported_volume_name = manager.get_pvc_volume(pvc_crd)
        sleep(60)
        csi_volume = manager.get_volume_from_array(globals.hpe3par_cli, imported_volume_name)
        vol_has_diff, diff = compare_volumes(volume, csi_volume)
        assert vol_has_diff is False, "After import volume properties are changed. Modified properties are %s" % diff
        logging.getLogger().info("\nImported volume's properties have been verified successfully, all property values retain.")
        pod_obj = create_verify_pod(yml, globals.hpe3par_cli, pvc_obj, imported_volume_name, globals.access_protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        delete_vol_from_array(globals.hpe3par_cli, vol_name)
        cleanup(None, sc, pvc_obj, pod_obj)
        #if hpe3par_cli is not None:
        #    hpe3par_cli.logout()


def delete_vol_from_array(hpe3par_cli, vol_name):
    try:
        logging.getLogger().info("In delete_vol_from_array() :: vol_name :: %s" % vol_name)
        volume = manager.get_volume_from_array(hpe3par_cli, vol_name)
        if volume is not None:
            hpe3par_cli.deleteVolume(vol_name)
    except (HTTPConflict, HTTPNotFound, HTTPForbidden) as e:
        logging.getLogger().info("Exception from delete_vol_from_array :: %s " % e)
    except Exception as e:
        logging.getLogger().info("Exception in delete_vol_from_array :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def cleanup(secret, sc, pvc, pod):
    logging.getLogger().info("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    logging.getLogger().info("pod :: %s, pvc :: %s, sc :: %s" % (pod, pvc, sc))
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
        """assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')"""
        flag = manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos")
        if flag is False:
            logging.getLogger().error("CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos'))
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", sc.metadata.namespace) is False:
        manager.delete_sc(sc.metadata.name)
    """if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is False:
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)"""
    logging.getLogger().info("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")


def cleanup_crd(snapshot_name, snapclass_name):
    logging.getLogger().info("====== cleanup_crd :START =========")
    # logging.info("====== cleanup after failure:START =========")
    if snapshot_name is not None:# and manager.check_if_crd_deleted(snapshot_name, "volumesnapshots") is False:
        manager.delete_snapshot(snapshot_name)
    if snapclass_name is not None:# and manager.check_if_crd_deleted(snapclass_name, "volumesnapshotclasses") is False:
        manager.delete_snapclass(snapclass_name)
    logging.getLogger().info("====== cleanup_crd :END =========")
    # logging.info("====== cleanup after failure:END =========")


def delete_resources(hpe3par_cli, secret, sc, pvc, pod, protocol):
    timeout = 600
    try:
        assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                              pod.metadata.name
        assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is True, \
            "Pod %s is not deleted yet " % pod.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc.spec.volume_name)
        # logging.getLogger().info(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)

        if protocol == 'iscsi':
            hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, volume_name)
            iscsi_ips = manager.get_iscsi_ips(hpe3par_cli)
            flag, disk_partition = manager.verify_by_path(iscsi_ips, pod.spec.node_name)
            flag, ip = manager.verify_deleted_partition(iscsi_ips, pod.spec.node_name)
            assert flag is True, "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip

            paths = manager.verify_deleted_multipath_entries(pod.spec.node_name, hpe3par_vlun)
            assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

            # partitions = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
            # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
            flag = manager.verify_deleted_lsscsi_entries(pod.spec.node_name, disk_partition)
            logging.getLogger().info("flag after deleted lsscsi verificatio is %s " % flag)
            assert flag, "lsscsi verification failed for vlun deletion"

        # Verify crd for unpublished status
        try:
            assert manager.verify_pvc_crd_published(pvc.spec.volume_name) is False, \
                "PVC CRD %s Published is true after Pod is deleted" % pvc.spec.volume_name
            logging.getLogger().info("PVC CRD published is false after pod deletion.")
            # logging.warning("PVC CRD published is false after pod deletion.")
        except Exception as e:
            logging.getLogger().info("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
            # logging.error("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        # pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # logging.getLogger().info("PVC crd after PVC object deletion :: %s " % pvc_crd)
        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
        sleep(30)
        assert manager.verify_delete_volume_on_3par(hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC") is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret",
                                        namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name
    except Exception as e:
        logging.getLogger().info("Exception in delete_resource() :: %s " % e)


def prepare_options(yaml_values, hpe3par_version):
    options = {}
    if 'comment' in yaml_values.keys():
        options['comment'] = yaml_values['comment']
    if 'snapCPG' in yaml_values.keys():
        options['snapCPG'] = yaml_values['snapCPG']
    if yaml_values['provisioning'] == "tpvv":
        options['tpvv'] = True
    if yaml_values['provisioning'] == "dedup":
        options['tdvv'] = True
    if yaml_values['provisioning'] == "reduce":
        options['tdvv'] = True
    if 'compression' in yaml_values.keys():
        if yaml_values['compression'] is True or yaml_values['compression'] == 'true':
            options['compression'] = True
        if yaml_values['compression'] is False or yaml_values['compression'] == 'false':
            options['compression'] = False
    return options

def create_vol_in_array(hpe3par_cli, options, vol_name='test-importVol', cpg_name='CI_CPG', size=10240):
    try:
        logging.getLogger().info("In create_vol_in_array() :: vol_name :: %s, cpg_name :: %s, size :: %s, options :: %s" % (vol_name,
                                                                                                         cpg_name, size, options))
        response = hpe3par_cli.createVolume(vol_name, cpg_name, size, options)
        logging.getLogger().info("Create volume response %s" % response)
        volume = manager.get_volume_from_array(hpe3par_cli, vol_name)
        return volume, None
    except (HTTPConflict, HTTPBadRequest, HTTPForbidden) as e:
        logging.getLogger().info("Exception from create_vol_in_array :: %s " % e)
        return None, e
    except Exception as e:
        logging.getLogger().info("Exception in create_vol_in_array :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def compare_volumes(vol1, vol2):
    #import pdb;pdb.set_trace()
    logging.getLogger().info("In compare_volumes()")
    logging.getLogger().info("vol1 :: %s" % vol1)
    logging.getLogger().info("vol2 :: %s" % vol2)

    flag = False
    diff_keys = {}
    try:
        for key, value in vol1.items():
            # if key == 'name' or key == 'links':
            #    continue
            if key not in ['deduplicationState', 'compressionState', 'provisioningType', 'copyType', 'userCPG',
                           'snapCPG']:
                continue
            if key in vol2 and vol1[key] != vol2[key]:
                diff_keys[key] = value
                flag = True

        return flag, diff_keys
    except Exception as e:
        logging.getLogger().info("Exception in compare_volumes :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def create_verify_pod(yml, hpe3par_cli, pvc_obj, imported_volume_name, protocol, pod_run=True, pod_message=''):
    pod = manager.create_pod(yml)
    flag, pod_obj = manager.check_status(None, pod.metadata.name, kind='pod', status='Running',
                                         namespace=pod.metadata.namespace)

    logging.getLogger().info("pod_run :: %s " % pod_run)
    logging.getLogger().info("pod_message :: %s " % pod_message)
    logging.getLogger().info("hpe3par_cli :: %s " % hpe3par_cli)
    logging.getLogger().info("flag :: %s " % flag)
    #logging.getLogger().info("pod_obj :: %s " % pod_obj)
    #logging.getLogger().info("pvc_obj :: %s " % pvc_obj)
    if pod_run:
        assert flag is True, "Published imported volume via pod %s, but it is not in Running state yet..." % pod.metadata.name
    else:
        assert flag is False
        logging.getLogger().info(pod_message)
        return pod_obj

    # Verify crd fpr published status
    assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is True, \
        "PVC CRD %s Published is false after Pod is running" % pvc_obj.spec.volume_name

    logging.getLogger().info("PVC CRD %s Published is True after Pod is running" % pvc_obj.spec.volume_name)

    hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, imported_volume_name)
    assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
        "Node for pod received from 3par and cluster do not match"

    logging.getLogger().info("Node for pod received from 3par and cluster do match")
    # verify_vlun(hpe3par_cli, hpe3par_vlun, pod_obj, protocol)

    return pod_obj
