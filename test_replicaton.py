import pytest
from time import sleep
import hpe_3par_kubernetes_manager as manager
from hpe3parclient.exceptions import HTTPNotFound
import logging
import globals
import yaml
import pdb
from threading import Thread
import datetime

# global variable to be shared in thread
pod_status_check_done = False
all_pods_running_time = 0

timeout = globals.status_check_timeout
globals.replication_test = True
sec_hpe3par_cli = None
prim_hpe3par_cli = None
prim_array_ip = None
sec_array_ip = None
pod_map = {}
# sc = None
# pvc_obj = None
# pod_obj = None
'''iscsi_ips = None
disk_partition = None
partition_map = {}
device_info_yaml = None
sc_yaml = None
# volume_name = None
# hpe3par_vlun = None
# rcg_name = None
secondary_rcg_name = None

prim_rcg_group = None
sec_rcg_group = None
'''
prim_secret = None
sec_secret = None

PORT_STATE_READY = 4
PORT_TYPE_RCIP = 7


@pytest.fixture(scope="module", autouse=True)
def secret():
    global prim_hpe3par_cli, sec_hpe3par_cli, prim_array_ip, sec_array_ip, prim_secret, sec_secret

    sec_secret_yaml = "%s/replication/sec_secret.yaml" % globals.yaml_dir
    prim_secret_yaml = "%s/replication/prim_secret.yaml" % globals.yaml_dir

    # Create secret for secondary array
    sec_secret = manager.create_secret(sec_secret_yaml, globals.namespace)
    hpe3par_ip, hpe3par_username, hpe3par_pwd = manager.read_array_prop(sec_secret_yaml)
    sec_array_ip = hpe3par_ip
    sec_hpe3par_cli = manager.get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd)

    # Create secret for primary array
    prim_secret = manager.create_secret(prim_secret_yaml, globals.namespace)
    hpe3par_ip, hpe3par_username, hpe3par_pwd = manager.read_array_prop(prim_secret_yaml)
    prim_array_ip = hpe3par_ip
    prim_hpe3par_cli = manager.get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd)

    yield
    sec_hpe3par_cli.logout()
    prim_hpe3par_cli.logout()
    if prim_secret is not None and manager.check_if_deleted(2, prim_secret.metadata.name, "Secret",
                                                            namespace=prim_secret.metadata.namespace) is False:
        manager.delete_secret(prim_secret.metadata.name, prim_secret.metadata.namespace)
    if sec_secret is not None and manager.check_if_deleted(2, sec_secret.metadata.name, "Secret",
                                                           namespace=sec_secret.metadata.namespace) is False:
        manager.delete_secret(sec_secret.metadata.name, sec_secret.metadata.namespace)


@pytest.mark.skip(reason="skipped as not implementation yet")
def test_replication_qw():
    global prim_hpe3par_cli, sec_hpe3par_cli
    sc = None
    pvc = None
    pod = None
    device_info_yaml = None
    primary_rcg_name = None
    # global rcg_name, secondary_rcg_name
    # global partition_map
    try:
        # Prerequisite
        # Verify if RCIP ports are in ready state on both arrays
        assert verify_port_state(prim_hpe3par_cli.getIPPorts(), port_type=PORT_TYPE_RCIP) is True, \
            "RCIP ports are not in ready state on primary array"
        logging.getLogger().info("Succesfully verified rcip ports on primary array")
        assert verify_port_state(sec_hpe3par_cli.getIPPorts(), port_type=PORT_TYPE_RCIP) is True, \
            "RCIP ports are not in ready state on secondary array"
        logging.getLogger().info("Succesfully verified rcip ports on secondary array")

        # get primary and secondary array names
        prim_sys_name = get_system_name(prim_hpe3par_cli)
        sec_sys_name = get_system_name(sec_hpe3par_cli)

        # Verify is secondary array is set as QW target on primary and vice-versa on secondary array
        flag, qw_server_prim = verify_rcopy_target(prim_hpe3par_cli, sec_sys_name)
        assert flag is True, \
            "Failed to verify secondary array as target on primary array"
        logging.getLogger().info("Succesfully verified remote copy targets on primary array")
        flag, qw_server_sec = verify_rcopy_target(prim_hpe3par_cli, sec_sys_name)
        assert flag is True, \
            "Failed to verify primary array as target on secondary array"
        logging.getLogger().info("Succesfully verified remote copy targets on secondary array")

        # Verify if qw_server ip received from priamary and secondary arrays is same
        assert qw_server_prim == qw_server_sec, "QW server IP mismatch in primary and secondary arrays"
        # ssh to QW machine and check if qw service is started
        qw_service_status = manager.get_command_output(qw_server_prim, "systemctl list-units | grep qwserv",
                                                       password='12iso*help')
        logging.getLogger().info(qw_service_status)
        if qw_service_status is not None and len(qw_service_status) > 0:
            qw_service_status = qw_service_status[0]
        assert "Quorum Witness server daemon" in qw_service_status and "loaded" in qw_service_status and \
               "active" in qw_service_status and "running" in qw_service_status, \
            "QW service is not running on QW server %s" % qw_server_prim
        logging.getLogger().info("Successfully verified the setup. Now lets verify replication...")

        sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir
        pvc_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
        pod_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir
        """
        # Create replication CRD to hold device info
        #device_info = manager.create_crd(device_info_yaml, "HPEReplicationDeviceInfo")

        #pytest.exit("Received remotecopytargets") """

        # Create volume, publish it and verify multipath. Check for active and host entries
        # corresponding to primary and secondary array respectively.
        sc, pvc, pod, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, volume_name, hpe3par_vlun, pvc_crd = \
            create_verify_obj(device_info_yaml, sc_yaml, pvc_yaml, pod_yaml)

        pdb.set_trace()
        # Creating failover. Bring down RCIP links on primary array to drop communication from primary array
        # to QW
        logging.getLogger().info("================================ Bringing rcip links down for failover to happen...")
        command = "controlport rcip state down -f 1:2:1; controlport rcip state down -f 0:2:1; " \
                  "onallnodes iptables -A OUTPUT -p tcp --dport 8080 -d %s -j DROP" % qw_server_prim
        # prim_failover_output = manager.execute_command_on_array(prim_array_ip, command=command)
        logging.getLogger().info("failover command :: %s" % command)
        #prim_failover_output = manager.get_command_output(qw_server_prim, command, password="12iso*help")
        prim_failover_output = manager.get_command_output(prim_array_ip, command, password="ssmssm")
        logging.getLogger().info("Failover done. %s" % prim_failover_output)
        pdb.set_trace()

        sleep(60)
        # Verify status and role of RCG on primary and secondary array
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary', action='failover')
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary',
                                                            action='failover')

        # check multipath entries. Multipath should mapped to secondary
        primary_hpe3par_vlun = manager.get_3par_vlun(prim_hpe3par_cli, volume_name)
        flag, disk_partition_mod, partition_map_temp = manager.verify_multipath(primary_hpe3par_vlun, disk_partition)
        logging.getLogger().info("partition_map :: %s" % partition_map)
        logging.getLogger().info("partition_map_temp :: %s" % partition_map_temp)
        assert partition_map['active'] != partition_map_temp['ghost'] or \
               partition_map['ghost'] != partition_map_temp['active'],\
               "Multipath entries are not mapped to secondary array after failover."
        logging.getLogger().info("Multipath entries are mapped to secondary array after failover.")

        # Bring up RCIP links on primary array
        logging.getLogger().info("===================Now bring up rcip links up to set for recovery...")
        command = "controlport rcip state up -f 1:2:1; controlport rcip state up -f 0:2:1; " \
                  "onallnodes iptables -A OUTPUT -p tcp --dport 8080 -d %s -j DROP" % qw_server_prim
        # prim_failover_output = manager.execute_command_on_array(prim_array_ip, command=command)
        logging.getLogger().info("Bring up rcip links command :: %s" % command)
        prim_failover_output = manager.get_command_output(prim_array_ip, command, password="ssmssm")
        logging.getLogger().info("RCIP links are up now. %s" % prim_failover_output)

        pdb.set_trace()
        # stop rcg before recover
        # prim_hpe3par_cli.stopRemoteCopy(primary_rcg_name)
        # Recover RCG
        logging.getLogger().info("===================== Recover rcg on secondary array")
        # sec_hpe3par_cli.recoverRemoteCopyGroupFromDisaster(secondary_rcg_name, action=9)
        command = "setrcopygroup recover -f %s" % secondary_rcg_name
        sec_recover_output = manager.get_command_output(sec_array_ip, command, password="ssmssm")
        logging.getLogger().info("Recover command o/p :: %s" % sec_recover_output)
        pdb.set_trace()
        # check status and role of rcg on both arrays
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary', action='recovery')
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary',
                                                            action='recovery')

        # Restore RCG
        logging.getLogger().info("===================== Restore rcg on secondary array")
        # sec_hpe3par_cli.recoverRemoteCopyGroupFromDisaster(secondary_rcg_name, action=10)
        command = "setrcopygroup restore -f %s" % secondary_rcg_name
        sec_restore_output = manager.get_command_output(sec_array_ip, command, password="ssmssm")
        logging.getLogger().info("Restore command o/p :: %s" % sec_restore_output)
        pdb.set_trace()
        # check status and role of rcg on both arrays
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary', action='restore')
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary',
                                                            action='restore')
        # check multipath entries. Multipath should mapped to primary again.
        flag, disk_partition_mod, partition_map_temp = manager.verify_multipath(primary_hpe3par_vlun, disk_partition)
        assert partition_map['active'] != partition_map_temp['active'] or \
               partition_map['ghost'] != partition_map_temp['ghost'], \
               "Multipath entries are not mapped to primary array after restore."
        logging.getLogger().info("Multipath entries are mapped to primary array after restore.")

        delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod,
                          iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd)

    except Exception as e:
        logging.getLogger().error("Exception in test_replication_qw for replication :: %s" % e)
        raise e

    finally:
        cleanup(sc, pvc, pod)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_crud():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    # global sc, pvc_obj, pod_obj, iscsi_ips, disk_partition
    sc = None
    pvc = None
    pod = None
    primary_rcg_name = None
    device_info_yaml = None
    try:
        """
            1. Create secondary secret
            2. Create replication crd (secondary array parameters should be given)
            3. Create primary secret
            4. Create sc and pvc 
            5. Volume should be part of rcg on both the arrays
            6. Create pod
            7. VLUNs to be created on both the arrays (active state on primary and standby state on secondary)
            8.multipath -ll entries should be seen as active ready and active ghos
            :return: 
        """
        sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir
        pvc_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
        pod_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        sc, pvc, pod, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, volume_name, hpe3par_vlun, pvc_crd = create_verify_obj(device_info_yaml, sc_yaml, pvc_yaml, pod_yaml)
        logging.getLogger().info("iscsi_ips :: %s" % iscsi_ips)
        delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd)

    except Exception as e:
        logging.getLogger().error("Exception in test_crud for replication :: %s" % e)
        raise e

    finally:
        cleanup(sc, pvc, pod)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_clone():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    sc = None
    pvc = None
    pod = None
    clone_pvc = None
    clone_pod = None
    device_info_yaml = None
    primary_rcg_name = None
    try:
        sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir
        base_pvc_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
        pod_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        # Create base PVC, publish it and verify vluns
        logging.getLogger().info("Create base volume and publish. Verify its vlun that active and host entries are created")
        sc, pvc, pod, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, \
        volume_name, hpe3par_vlun, pvc_crd = create_verify_obj(device_info_yaml, sc_yaml, base_pvc_yaml, pod_yaml)
        logging.getLogger().info("iscsi_ips :: %s" % iscsi_ips)
        logging.getLogger().info("Base volume creation and verification completed successfully")

        # Now create clone, publish. For clone, volume will not be created on secondary array
        logging.getLogger().info("Now create clone and publish it.")
        clone_pvc_yaml = "%s/replication/clone_pvc.yaml" % globals.yaml_dir
        clone_pvc, clone_volume_name = create_pvc(clone_pvc_yaml)
        assert manager.verify_clone_crd_status(clone_pvc.spec.volume_name) is True, \
            "Clone PVC CRD is not yet completed"
        clone_pvc_crd = manager.get_pvc_crd(clone_pvc.spec.volume_name)
        clone_volume_name = manager.get_pvc_volume(clone_pvc_crd)
        clone_volume = manager.get_volume_from_array(prim_hpe3par_cli, clone_volume_name)
        assert clone_volume is not None, "Clone Volume is not created on 3PAR for pvc %s " % volume_name
        logging.getLogger().info("Clone Volume is verified successfully at array")

        # Now publish clone
        logging.getLogger().info("Now publish clone volume and verify vluns. "
                                 "Only active entries will be seen in multipath ")
        clone_pod_yaml = "%s/replication/clone_pod.yaml" % globals.yaml_dir
        clone_pod = create_pod(clone_pod_yaml, clone_pvc.spec.volume_name)
        globals.replication_test = False
        iscsi_ips, disk_partition, partition_map, clone_hpe3par_vlun, clone_pvc_crd = verify_vluns(clone_volume_name, clone_pod, clone_pvc)
        logging.getLogger().info("Vlun verification completed successfully for clone pvc")

        logging.getLogger().info("Now unpublish clone volume and delete it. Verify cleanup...")
        delete_pod(clone_pod, clone_pvc.spec.volume_name)

        logging.getLogger().info("Now verify if vluns and multipath entries are deleted from worker node")
        verify_deleted_vluns(clone_pod, clone_pvc_crd, iscsi_ips, clone_hpe3par_vlun, disk_partition)

        logging.getLogger().info("Delete clone pvc now and verify")
        delete_verify_pvc(clone_pvc, clone_volume_name)

        logging.getLogger().info("Now unpublish base pvc and verify cleanup")
        globals.replication_test = True
        delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd)

    except Exception as e:
        logging.getLogger().error("Exception in test_clone for replication :: %s" % e)
        raise e

    finally:
        cleanup(None, clone_pvc, clone_pod)
        cleanup(sc, pvc, pod)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_expand_volume():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    sc = None
    pvc = None
    pod = None
    device_info_yaml = None
    primary_rcg_name = None
    try:
        sc_yaml = "%s/replication/sc_expand.yaml" % globals.yaml_dir
        pvc_yaml = "%s/replication/pvc_expand.yaml" % globals.yaml_dir
        pod_yaml = "%s/replication/pod_expand.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        # Create PVC, publish it and verify vluns
        logging.getLogger().info("Create volume and publish. Verify its vlun that active and host entries are created")
        sc, pvc, pod, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, \
        volume_name, hpe3par_vlun, pvc_crd = create_verify_obj(device_info_yaml, sc_yaml, pvc_yaml, pod_yaml)
        logging.getLogger().info("iscsi_ips :: %s" % iscsi_ips)
        logging.getLogger().info("Volume creation and verification completed successfully")

        # Now expand volume. It will fail as remote copy is started.
        logging.getLogger().info("Expand volume. RCG is started so volume expansion should fail...")
        # patch pvc for expand size
        size_in_gb = '50'
        patch_json = {'spec': {'resources': {'requests': {'storage': size_in_gb + 'Gi'}}}}
        mod_pvc = manager.patch_pvc(pvc.metadata.name, pvc.metadata.namespace, patch_json)
        #logging.getLogger().info(mod_pvc)

        logging.getLogger().info("Now check if volume is expanded...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid,
                                                           reasons=['VolumeResizeFailed'])
        expected_failure_message = "VV %s is currently in a started remote copy group" % volume_name
        assert status == 'VolumeResizeFailed' and expected_failure_message in message, f"{message}"
        logging.getLogger().info("status :: %s, message :: %s" % (status, message))
        logging.getLogger().info("Volume expansion failed as volume is part of started RCG. Stop RCG and try again...")

        logging.getLogger().info("stop RCG to allow volume expansion...")
        prim_hpe3par_cli.stopRemoteCopy(primary_rcg_name)
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary', 'stopped')
        assert primary_rcg_flag, f"RCG is not stopped on primary array"
        rcg = prim_hpe3par_cli.getRemoteCopyGroup(primary_rcg_name)
        logging.getLogger().info("RCG after stop request... \n%s" % rcg)

        logging.getLogger().info("Now try again for expand after RCG is stopped.")
        mod_pvc = manager.patch_pvc(pvc.metadata.name, pvc.metadata.namespace, patch_json)
        #logging.getLogger().info(mod_pvc)
        logging.getLogger().info("Now check if volume is expanded...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid,
                                                           reasons=['FileSystemResizeSuccessful'])
        logging.getLogger().info("status :: %s, message :: %s" % (status, message))
        if status != 'FileSystemResizeSuccessful':
            status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                               namespace=pvc.metadata.namespace, uid=pvc.metadata.uid,
                                                               reasons=['VolumeResizeFailed'])
            assert status == 'FileSystemResizeSuccessful', f"{message}"
        logging.getLogger().info("Volume resized successfully.")

        # Start RemoteCopyGroup now...
        logging.getLogger().info("Start RCG again.")
        prim_hpe3par_cli.startRemoteCopy(primary_rcg_name)

        # Now check if volume on primary has increased size
        logging.getLogger().info("Now verify size of volume on primary array")
        volume = manager.get_volume_from_array(prim_hpe3par_cli, volume_name)
        logging.getLogger().info("Volume on primary array :: %s" % volume)
        assert volume['sizeMiB'] == int(size_in_gb) * 1024, "Volume on primary array does not have updated size"

        # Now check if volume on secondary has increased size
        logging.getLogger().info("Verify size of volume on secondary array")
        volume = manager.get_volume_from_array(sec_hpe3par_cli, volume_name)
        logging.getLogger().info("Volume on secondary array :: %s" % volume)
        assert volume['sizeMiB'] == int(size_in_gb) * 1024, "Volume on secondary array does not have updated size"

        # Check if PVC has increased size
        logging.getLogger().info("Verify size of PVC on cluster")
        mod_pvc = manager.hpe_read_pvc_object(pvc.metadata.name, pvc.metadata.namespace)
        #logging.getLogger().info("PVC after expansion %s" % mod_pvc)
        # assert mod_pvc['spec']['resources']['requests']['storage'] == "%sGi" % size_in_gb, "PVC %s does not have updated size" % pvc.metadata.name
        assert mod_pvc.spec.resources.requests['storage'] == "%sGi" % size_in_gb, "PVC %s does not have updated size" % pvc.metadata.name

        logging.getLogger().info("Now unpublish pvc and verify cleanup")
        delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd)

    except Exception as e:
        logging.getLogger().error("Exception in volume expansion test with replication :: %s" % e)
        raise e

    finally:
        cleanup(sc, pvc, pod)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_add_remove_volume_rcg():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    sc = None
    pvc1 = None
    pod1 = None
    pvc2 = None
    device_info_yaml = None
    primary_rcg_name = None
    try:
        sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir
        pvc1_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
        pvc2_yaml = "%s/replication/pvc2.yaml" % globals.yaml_dir
        pod1_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        # Create RCG on array
        primary_rcg_name = 'ci-3par-csp-rcg-crud'
        #targets = globals.rep_targets.split(",")
        policies = {'autoRecover': False, 'pathManagement': True, 'autoFailover': True}

        targets = [{'targetName': 'CSIM-EOS12_1611702', 'mode': 1, 'userCPG': 'CI_CPG', 'snapCPG': 'CI_CPG'}]

        optional = {
            "localSnapCPG": "CI_CPG",
            "localUserCPG": "CI_CPG"
            # "domain": "some-domain"  # Specifies the attributes of
            # the target of the
            # remote-copy group.
        }

        logging.getLogger().info("Create RCG on array")
        prim_hpe3par_cli.createRemoteCopyGroup(primary_rcg_name, targets, optional=optional)
        prim_hpe3par_cli.modifyRemoteCopyGroup(primary_rcg_name, optional={'targets': [{'targetName': 'CSIM-EOS12_1611702', 'policies': policies}]})
        prim_hpe3par_cli.startRemoteCopy(primary_rcg_name)
        # rcg = prim_hpe3par_cli.getRemoteCopyGroup(rcg_name)
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary')
        assert primary_rcg_flag is True, \
            "Remote Copy Groups verification failed on primary array"
        logging.getLogger().info("RemoteCopyGroup %s verification succeeded on primary array" % primary_rcg_name)
        secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary')
        assert secondary_rcg_flag is True, \
            "Remote Copy Groups verification failed on secondary array"
        logging.getLogger().info("RemoteCopyGroup %s verification succeeded on secondary array" % secondary_rcg_name)

        # Create replication CRD to hold device info
        device_info = create_device_info(device_info_yaml)

        # Create storage class
        sc = create_sc(sc_yaml)

        # Create PVC
        logging.getLogger().info("Create PVC and add it to rcg. Verify if pvc is part of rcg on both arrays.")
        pvc1, volume_name = create_pvc(pvc1_yaml)
        # rcg_volume = prim_hpe3par_cli.getRemoteCopyGroupVolume(rcg_name, volume_name)
        # logging.getLogger().info("Volume from RemotecopyGroup :: \n%s" % rcg_volume)
        assert check_volume_in_rcg(volume_name, primary_rcg_name, prim_hpe3par_cli) is True, \
            "Failed to add PVC %s to RCG %s on primary" % (pvc1.metadata.name, primary_rcg_name)
        logging.getLogger().info("Verified PVC %s is part of rcg %s on primary array." % (pvc1.metadata.name, primary_rcg_name))

        # rcg_volume = sec_hpe3par_cli.getRemoteCopyGroupVolume(secondary_rcg_name, volume_name)
        # logging.getLogger().info("Volume from RemotecopyGroup :: \n%s" % rcg_volume)
        assert check_volume_in_rcg(volume_name, secondary_rcg_name, sec_hpe3par_cli) is True, \
            "Failed to add PVC %s to RCG %s on secondary array" % (pvc1.metadata.name, secondary_rcg_name)
        logging.getLogger().info("Verified PVC %s is part of rcg %s on secondary array." % (pvc1.metadata.name, secondary_rcg_name))

        logging.getLogger().info("Now publish the pvc and verify")
        pod1 = create_pod(pod1_yaml, pvc1.spec.volume_name)
        # Now verify vluns, multipath and by-path/by-id entries
        iscsi_ips, disk_partition, partition_map, hpe3par_vlun, pvc1_crd = verify_vluns(volume_name, pod1, pvc1)

        logging.getLogger().info("Create another pvc and add it to rcg")
        pvc2, volume_name_2 = create_pvc(pvc2_yaml)
        # rcg_volume = prim_hpe3par_cli.getRemoteCopyGroupVolume(rcg_name, volume_name_2)
        # logging.getLogger().info("Volume from RemotecopyGroup :: \n%s" % rcg_volume)
        assert check_volume_in_rcg(volume_name_2, primary_rcg_name, prim_hpe3par_cli) is True, "Failed to add PVC %s to RCG %s" % (pvc2.metadata.name, rcg_name)
        logging.getLogger().info("Verified PVC %s is part of rcg %s on primary array." % (pvc2.metadata.name, primary_rcg_name))

        # rcg_volume = sec_hpe3par_cli.getRemoteCopyGroupVolume(secondary_rcg_name, volume_name)
        # logging.getLogger().info("Volume from RemotecopyGroup :: \n%s" % rcg_volume)
        secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
        assert check_volume_in_rcg(volume_name_2, secondary_rcg_name, sec_hpe3par_cli) is True, \
            "Failed to add PVC %s to RCG %s on secondary array" % (pvc2.metadata.name, secondary_rcg_name)
        logging.getLogger().info(
            "Verified PVC %s is part of rcg %s on secondary array." % (pvc2.metadata.name, secondary_rcg_name))

        logging.getLogger().info("Unpublish pvc1 %s, delete and verify it should not be part of rcg anymore on either of arrays.")
        delete_pod(pod1, pvc1.spec.volume_name)
        verify_deleted_vluns(pod1, pvc1_crd, iscsi_ips, hpe3par_vlun, disk_partition)

        delete_verify_pvc(pvc1, volume_name)
        assert check_volume_in_rcg(volume_name, primary_rcg_name, prim_hpe3par_cli) is False, \
            "PVC %s is still part of RCG %s on primary array" % (pvc1.metadata.name, primary_rcg_name)
        logging.getLogger().info(
            "Verified PVC %s is not part of rcg %s on primary array." % (pvc1.metadata.name, primary_rcg_name))

        assert check_volume_in_rcg(volume_name, secondary_rcg_name, sec_hpe3par_cli) is False, \
            "PVC %s is still part of RCG %s on secondary array" % (pvc1.metadata.name, secondary_rcg_name)
        logging.getLogger().info(
            "Verified PVC %s is not part of rcg %s on secondary array." % (pvc1.metadata.name, secondary_rcg_name))

        logging.getLogger().info("Delete pvc2 and verify")
        delete_verify_pvc(pvc2, volume_name_2)
        assert check_volume_in_rcg(volume_name_2, primary_rcg_name, prim_hpe3par_cli) is False, \
            "PVC %s is still part of RCG %s on primary array" % (pvc2.metadata.name, primary_rcg_name)
        logging.getLogger().info("Verified PVC %s is not part of rcg %s on primary array." % (pvc2.metadata.name, primary_rcg_name))

        assert check_volume_in_rcg(volume_name_2, secondary_rcg_name, sec_hpe3par_cli) is False,\
            "PVC %s is still part of RCG %s on secondary array" % (pvc2.metadata.name, secondary_rcg_name)
        logging.getLogger().info(
            "Verified PVC %s is not part of rcg %s on secondary array." % (pvc2.metadata.name, secondary_rcg_name))

        logging.getLogger().info("Verify rcg still exists on both arrays and had no volumes as part.")
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary')
        assert primary_rcg_flag is True, \
            "Remote Copy Groups verification failed on primary array"
        logging.getLogger().info("RemoteCopyGroup %s verification succeeded on primary array" % primary_rcg_name)
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary')
        assert secondary_rcg_flag is True, \
            "Remote Copy Groups verification failed on secondary array"
        logging.getLogger().info("RemoteCopyGroup %s verification succeeded on secondary array" % secondary_rcg_name)

        logging.getLogger().info("Deleting rcg...")
        prim_hpe3par_cli.stopRemoteCopy(primary_rcg_name)
        prim_hpe3par_cli.removeRemoteCopyGroup(primary_rcg_name)

        assert check_rcg_exists(primary_rcg_name, prim_hpe3par_cli) is None, "RCG is not yet deleted from primary array"
        logging.getLogger().info("RCG is deleted from primary array")

        assert check_rcg_exists(secondary_rcg_name, sec_hpe3par_cli) is None, "RCG is not yet deleted from secondary array"
        logging.getLogger().info("RCG is deleted from secondary array")

        logging.getLogger().info("Delete device info crd")
        delete_verify_device_info(device_info_yaml, primary_rcg_name)
    except Exception as e:
        logging.getLogger().error("Exception while verifying add/remove pvc to existing rcg :: %s" % e)
        raise e

    finally:
        cleanup(None, pvc1, pod1)
        cleanup(sc, pvc2, None)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_manual_switchover_and_revert():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    # global sc, pvc_obj, pod_obj, iscsi_ips, disk_partition
    sc = None
    pvc = None
    pod = None
    primary_rcg_name = None
    device_info_yaml = None
    try:
        """
            1. Create secondary secret
            2. Create replication crd (secondary array parameters should be given)
            3. Create primary secret
            4. Create sc and pvc 
            5. Volume should be part of rcg on both the arrays
            6. Create pod
            7. VLUNs to be created on both the arrays (active state on primary and standby state on secondary)
            8.multipath -ll entries should be seen as active ready and active ghos
            :return: 
        """
        sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir
        pvc_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
        pod_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        sc, pvc, pod, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, volume_name, hpe3par_vlun, pvc_crd = create_verify_obj(device_info_yaml, sc_yaml, pvc_yaml, pod_yaml)

        #pdb.set_trace()
        # Creating switchover
        #prim_hpe3par_cli.stopRemoteCopy(primary_rcg_name)
        prim_hpe3par_cli.recoverRemoteCopyGroupFromDisaster(primary_rcg_name, action=8)
        #prim_hpe3par_cli.startRemoteCopy(primary_rcg_name)
        logging.getLogger().info("Switchover done.")
        logging.getLogger().info("Sleeping for 2 mins...")
        sleep(120)
        logging.getLogger().info("Over from sleeping...")
        # check status and role of rcg on both arrays
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary',
                                                        action='switchover')
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary',
                                                            action='switchover')

        # check multipath entries. Multipath should mapped to secondary
        primary_hpe3par_vlun = manager.get_3par_vlun(prim_hpe3par_cli, volume_name)
        flag, disk_partition_mod, partition_map_temp = manager.verify_multipath(primary_hpe3par_vlun, disk_partition)
        logging.getLogger().info("partition_map :: %s" % partition_map)
        logging.getLogger().info("partition_map_temp :: %s" % partition_map_temp)
        assert sorted(partition_map['active']) == sorted(partition_map_temp['ghost']) and \
               sorted(partition_map['ghost']) == sorted(partition_map_temp['active']), \
            "Multipath entries are not mapped to secondary array after switchover."
        logging.getLogger().info("Multipath entries are mapped to secondary array after switchover.")

        # verify if multipath entries count is equal to vlun entries on array
        prim_active_vluns = manager.get_all_active_vluns(prim_hpe3par_cli, volume_name)
        sec_active_vluns = manager.get_all_active_vluns(sec_hpe3par_cli, volume_name)
        logging.getLogger().info("prim_active_vluns :: %s" % prim_active_vluns)
        logging.getLogger().info("sec_active_vluns :: %s" % sec_active_vluns)

        assert len(prim_active_vluns) == len(partition_map['active']), \
            "Multipath entries mismatch on cluster and primary array"
        assert len(sec_active_vluns) == len(partition_map['ghost']), \
            "Multipath entries mismatch on cluster and secondary array"

        #pdb.set_trace()
        # Restore RCG
        #sec_hpe3par_cli.stopRemoteCopy(secondary_rcg_name)
        sec_hpe3par_cli.recoverRemoteCopyGroupFromDisaster(secondary_rcg_name, action=8)
        logging.getLogger().info("Switchover done from secondary array of rcg %s" % secondary_rcg_name)
        logging.getLogger().info("Sleeping for 2 mins...")
        sleep(120)
        logging.getLogger().info("Over from sleeping...")
        #sec_hpe3par_cli.startRemoteCopy(secondary_rcg_name)
        # check status and role of rcg on both arrays
        primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary', action='switchover')
        secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary',
                                                            action='switchover')
        # check multipath entries. Multipath should mapped to primary again.
        flag, disk_partition_mod, partition_map_temp = manager.verify_multipath(primary_hpe3par_vlun, disk_partition)
        logging.getLogger().info("partition_map :: %s" % partition_map)
        logging.getLogger().info("partition_map_temp :: %s" % partition_map_temp)
        assert sorted(partition_map['active']) == sorted(partition_map_temp['active']) and \
               sorted(partition_map['ghost']) == sorted(partition_map_temp['ghost']), \
            "Multipath entries are not mapped to primary array after restore."
        logging.getLogger().info("Multipath entries are mapped to primary array after restore.")

        # verify if multipath entries count is equal to vlun entries on array
        prim_active_vluns = manager.get_all_active_vluns(prim_hpe3par_cli, volume_name)
        sec_active_vluns = manager.get_all_active_vluns(sec_hpe3par_cli, volume_name)
        logging.getLogger().info("prim_active_vluns :: %s" % prim_active_vluns)
        logging.getLogger().info("sec_active_vluns :: %s" % sec_active_vluns)

        assert len(prim_active_vluns) == len(partition_map['active']), \
            "Multipath entries mismatch on cluster and primary array"
        assert len(sec_active_vluns) == len(partition_map['ghost']), \
            "Multipath entries mismatch on cluster and secondary array"

        #pdb.set_trace()
        delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd)

    except Exception as e:
        logging.getLogger().error("Exception in test_crud for replication :: %s" % e)
        raise e

    finally:
        cleanup(sc, pvc, pod)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        pass


def test_scale_with_statefulset():
    global sec_hpe3par_cli
    global prim_hpe3par_cli
    global pod_map
    sc = None
    primary_rcg_name = None
    device_info_yaml = None
    pvc_name_pat = None
    pod_name_pat = None
    primary_rcg_name = None
    secondary_rcg_name = None
    try:
        """
            1. Create secondary secret
            2. Create replication crd (secondary array parameters should be given)
            3. Create primary secret
            4. Create sc with replication enabled statefulset
            5. Create statefulset - this will create pvc and pod (1 each as replicas given in statefulset is 1)
            6. Verify PVC for Bound and vlun entries for pod
            7. scale up to 50 and verify 50 pvc to be created and bound and vluns for 50 pods
            8. scale down to 30 and verification
            9. scale up to 60 and verification
            10. scale up to 100 and verification
            11. scale down to 50 and verification
            12. Delete statefulset - all pod must be deleted and cleanup. 
            13. Delete all PVCs amd verify. After all pvc are deleted, ALSO verify rcg are deleted from both arrays.
            13. Delete storage class and secrets.
        """
        sc_yaml = "%s/replication/sc_statefulset.yaml" % globals.yaml_dir
        statefulset_yaml = "%s/replication/statefulset.yaml" % globals.yaml_dir
        device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir

        # get rcg name from sc yaml
        primary_rcg_name = manager.read_value_from_yaml(sc_yaml, "StorageClass", "parameters:remoteCopyGroup")

        pod_name_pat = manager.read_value_from_yaml(statefulset_yaml, "StatefulSet", "metadata:name")
        #pvc_name_pat = manager.read_value_from_yaml(statefulset_yaml, "StatefulSet", "spec:volumeClaimTemplates:metadata:name")
        statefulset_map = manager.read_yaml(statefulset_yaml)
        pvc_name_pat = "%s-%s" % (statefulset_map[0]['spec']['volumeClaimTemplates'][0]['metadata']['name'], pod_name_pat)
        #pvc_name_pat = statefulset_map[0]['spec']['volumeClaimTemplates'][0]['metadata']['name']
        #pvc_name_pat = pvc_name_pat + "-" + pod_name_pat

        replica_count = manager.read_value_from_yaml(statefulset_yaml, "StatefulSet", "spec:replicas")

        logging.getLogger().info("pvc_name_pat :: %s" % pvc_name_pat)
        logging.getLogger().info("pod_name_pat :: %s" % pod_name_pat)
        logging.getLogger().info("replica_count :: %s" % replica_count)

        # Create replication CRD to hold device info
        device_info = create_device_info(device_info_yaml)

        # Create storage class
        sc = create_sc(sc_yaml)

        # Create statefulset
        statefulset = create_statefulset(statefulset_yaml)

        # Wait until RCG on both arrays is started
        while True:
            if check_rcg_exists(primary_rcg_name, prim_hpe3par_cli) is not None:
                break
            else:
                sleep(1)
        secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
        while True:
            if verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary') and \
                    verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary'):
                break
            else:
                sleep(1)
        logging.getLogger().info("RCG on primary and secondary array have been started.")

        logging.getLogger().info("========================== check pvc and pod is created after creation of "
                                 "statefulset")
        # Check if PVC and Pods are created
        verify_creation_after_scale(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name)

        # scale to 50 pods
        logging.getLogger().info("==================== Scaling up to 50 ========================")
        replica_count = 5
        scale_up(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name, statefulset.metadata.name)

        # scale down to 30 pods
        logging.getLogger().info("==================== Scaling down to 30 ========================")
        replica_count = 3
        scale_down(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name, secondary_rcg_name, statefulset.metadata.name)

        # Delete statefulset, pvc and verify cleanup
        manager.delete_statefulset(statefulset.metadata.name, statefulset.metadata.namespace)

        # Verify cleanup
        logging.getLogger().info("==================== StatefulSet deleted, verifying cleanup ========================")
        replica_count = 0
        scale_down(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name, secondary_rcg_name, statefulset.metadata.name)

        '''
        iscsi_ips = manager.get_iscsi_ips(prim_hpe3par_cli)
        if globals.replication_test:
            iscsi_ips.extend(manager.get_iscsi_ips(sec_hpe3par_cli))

        for i in range(replica_count):
            # verify pod deletion
            # verify vlun cleanup
            # delete pvc
            # verify volume deletion from both arrays and from rcg

            #pdb.set_trace()
            pvc_name = "%s-%s" % (pvc_name_pat, i)

            pvc = manager.hpe_read_pvc_object(pvc_name, globals.namespace)
            vol_name_cluster = pvc.spec.volume_name

            logging.getLogger().info("vol_name_cluster :: %s" % vol_name_cluster)
            pod_name = "%s-%s" % (pod_name_pat, i)
            pod_obj = pod_map[pod_name]['pod']
            vol_name_on_array = pod_map[pod_name]['vol_name_array']
            hpe3par_vlun = pod_map[pod_name]['vlun']
            disk_partition = pod_map[pod_name]['disk_partition']
            verify_pod_deletion(pod_name, globals.namespace,vol_name_cluster)
            verify_deleted_vluns(pod_obj, vol_name_on_array, iscsi_ips, hpe3par_vlun, disk_partition)

            pvc_obj = pod_map[pod_name]['pvc']
            delete_verify_pvc(pvc_obj, vol_name_on_array)
            sleep(30)
            if i == replica_count-1:
                assert check_rcg_exists(primary_rcg_name, prim_hpe3par_cli) is None, \
                    "RCG %s still exists on primary array after deletion of last PVC" % primary_rcg_name
                assert check_rcg_exists(secondary_rcg_name, sec_hpe3par_cli) is None, \
                    "RCG %s still exists after on secondary array deletion of last PVC" % secondary_rcg_name
            else:
                # Verify removed from rcg
                assert check_volume_in_rcg(vol_name_on_array, primary_rcg_name, prim_hpe3par_cli) is False, \
                    "PVC %s is still part of rcg %s on primary array" % (pvc_name, primary_rcg_name)
                logging.getLogger().info(
                    "Verified PVC %s is no more part of rcg %s on primary array." % (pvc_name, primary_rcg_name))

                #secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
                # Verify volume is part of rcg on secondary array
                assert check_volume_in_rcg(vol_name_on_array, secondary_rcg_name, sec_hpe3par_cli) is False, \
                    "PVC %s is still part of rcg %s on secondary array" % (pvc_name, secondary_rcg_name)
                logging.getLogger().info(
                    "Verified PVC %s is no more part of rcg %s on secondary array." % (pvc_name, secondary_rcg_name))

        '''
        # delete storage class
        delete_verify_sc(sc)
        # delete replication crd and verify
        delete_verify_device_info(device_info_yaml, primary_rcg_name)
    except Exception as e:
        logging.getLogger().error("Exception in test_scale_with_statefulset for replication :: %s" % e)
        raise e
    finally:
        cleanup_statefulset(statefulset)
        for pod_name in pod_map.keys():
            pvc_obj = pod_map[pod_name]['pvc']
            cleanup(None, pvc_obj, None)
        cleanup_rep_crd(device_info_yaml, primary_rcg_name)
        cleanup(sc, None, None)
        pass


def scale_up(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name, statefulset_name):
    global pod_map

    command = "kubectl scale --replicas=%s statefulset/%s -n %s" % (replica_count, statefulset_name,
                                                                    globals.namespace)
    logging.getLogger().info("Command :: %s" % command)
    output = manager.get_command_output_string(command)
    logging.getLogger().info("Scaled :: %s" % output)

    logging.getLogger().info("================ Now verify after scaling to %s" % replica_count)

    # Check if PVC and Pods are created
    verify_creation_after_scale(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name)


def scale_down(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name, secondary_rcg_name,
               statefulset_name):
    global pod_map

    # replica_count = 30
    # pod_map len = 50
    # get list of pods from 30 t0 50 -> replica_count to len(pod_map)
    '''
    pod_map[pod_name] = {'vol_name_array': volume_name,
                             'pod': pod_obj,
                             'pvc': pvc_obj,
                             'vlun': hpe3par_vlun,
                             'disk_partition': disk_partition}
    '''
    command = "kubectl scale --replicas=%s statefulset/%s -n %s" % (replica_count, statefulset_name,
                                                                    globals.namespace)
    logging.getLogger().info("Command :: %s" % command)
    output = manager.get_command_output_string(command)
    logging.getLogger().info("Scaled :: %s" % output)

    logging.getLogger().info("================ Now verify after scaling to %s" % replica_count)

    iscsi_ips = manager.get_iscsi_ips(prim_hpe3par_cli)
    if globals.replication_test:
        iscsi_ips.extend(manager.get_iscsi_ips(sec_hpe3par_cli))

    # pdb.set_trace()
    for i in range(replica_count, len(pod_map)):
        pod_name = "%s-%s" % (pod_name_pat, i)

        pod_obj = pod_map[pod_name]['pod']
        vol_name_on_array = pod_map[pod_name]['vol_name_array']
        hpe3par_vlun = pod_map[pod_name]['vlun']
        disk_partition = pod_map[pod_name]['disk_partition']
        pvc_obj = pod_map[pod_name]['pvc']

        # Verify pod deletion and vlun cleanup
        verify_pod_deletion(pod_name, globals.namespace, pvc_obj.spec.volume_name)
        verify_deleted_vluns(pod_obj, pod_map[pod_name]['pvc_crd'], iscsi_ips, hpe3par_vlun, disk_partition)

        # Verify pvc deletion and cleanup
        pvc_name = pvc_obj.metadata.name
        delete_verify_pvc(pvc_obj, vol_name_on_array)

        if replica_count == 0 and i == len(pod_map) - 1:
            i = 0
            rcg_on_primary = check_rcg_exists(primary_rcg_name, prim_hpe3par_cli)
            rcg_on_secondary = check_rcg_exists(secondary_rcg_name, sec_hpe3par_cli)
            while True:
                if rcg_on_primary is not None:
                    rcg_on_primary = check_rcg_exists(primary_rcg_name, prim_hpe3par_cli)
                if rcg_on_secondary is not None:
                    rcg_on_secondary = check_rcg_exists(secondary_rcg_name, sec_hpe3par_cli)

                if rcg_on_primary is None and rcg_on_secondary is None:
                    break
                else:
                    if i > 20:
                        break
                    i += 1
                    sleep(1)

            assert i < 20, "RCGs %s and %s still exists on primary and secondary arrays respectively after deletion " \
                           "of last PVC" % (primary_rcg_name, secondary_rcg_name)
        else:
            # Verify removed from rcg
            assert check_volume_in_rcg(vol_name_on_array, primary_rcg_name, prim_hpe3par_cli) is False, \
                "PVC %s is still part of rcg %s on primary array" % (pvc_name, primary_rcg_name)
            logging.getLogger().info(
                "Verified PVC %s is no more part of rcg %s on primary array." % (pvc_name, primary_rcg_name))

            # secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
            # Verify volume is part of rcg on secondary array
            assert check_volume_in_rcg(vol_name_on_array, secondary_rcg_name, sec_hpe3par_cli) is False, \
                "PVC %s is still part of rcg %s on secondary array" % (pvc_name, secondary_rcg_name)
            logging.getLogger().info(
                "Verified PVC %s is no more part of rcg %s on secondary array." % (pvc_name, secondary_rcg_name))

    # Remove deleted pod entries from map
    for i in range(replica_count, len(pod_map)):
        pod_name = "%s-%s" % (pod_name_pat, i)
        pod_map.pop(pod_name)


def timer():
    global pod_status_check_done
    global all_pods_running_time
    all_pods_running_time = 0
    while pod_status_check_done is False:
        all_pods_running_time += 1
        sleep(1)


def verify_creation_after_scale(replica_count, pvc_name_pat, pod_name_pat, primary_rcg_name):
    logging.getLogger().info("replica_count :: %s" % replica_count)
    logging.getLogger().info("pvc_name_pat :: %s" % pvc_name_pat)
    logging.getLogger().info("pod_name_pat :: %s" % pod_name_pat)
    logging.getLogger().info("primary_rcg_name :: %s" % primary_rcg_name)

    global pod_map
    global pod_status_check_done, all_pods_running_time
    #pod_map.clear()

    pods_to_be_verified = []
    for i in range(len(pod_map), replica_count):
        pods_to_be_verified.append("%s-%s" % (pod_name_pat, i))

    # start timer
    pod_status_check_done = False
    thread1 = Thread(target=timer, name="timer")
    thread1.start()

    # check how long it takes to bring all pods to running
    while all_pods_running_time < 30 * 60:
        if len(pods_to_be_verified) == 0:
            pod_status_check_done = True
            break
        else:
            logging.getLogger().info("%s pods to be checked for status" % len(pods_to_be_verified))
            logging.getLogger().info("%s" % pods_to_be_verified)
            for pod_name in pods_to_be_verified:
                try:
                    pod = manager.hpe_get_pod(pod_name, globals.namespace)
                    flag, pod_obj = manager.check_status(5, pod.metadata.name, kind='pod', status='Running',
                                                         namespace=pod.metadata.namespace)
                    if flag is True:
                        pods_to_be_verified.remove(pod_name)
                except Exception as e:
                    logging.getLogger().info("Exception while checking pod status:: %s" % e)
                    pass

    logging.getLogger().info(
        f"======= After scaling up {len(pods_to_be_verified)} pods came to running in {str(datetime.timedelta(0, all_pods_running_time))} ")

    # pdb.set_trace()

    # Now verify volume on array and vlun for each pvc and other validations
    for i in range(len(pod_map) ,replica_count):
        pvc_name = "%s-%s" % (pvc_name_pat, i)
        #pdb.set_trace()
        pvc = manager.hpe_read_pvc_object(pvc_name, globals.namespace)
        flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        volume_name = manager.get_pvc_volume(pvc_crd)

        # Verify volume is created on both arrays
        verify_volume_on_arrays(volume_name, pvc_obj.metadata.name)

        # Verify newly created volume is part of rcg on both arrays
        verify_volume_in_rcgs(volume_name, primary_rcg_name, pvc_name)

        pod_name = "%s-%s" % (pod_name_pat, i)
        pod = manager.hpe_get_pod(pod_name, globals.namespace)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)

        # Now verify vluns, multipath and by-path/by-id entries
        iscsi_ips, disk_partition, partition_map, hpe3par_vlun, pvc_crd = verify_vluns(volume_name, pod_obj, pvc_obj)
        pod_map[pod_name] = {'vol_name_array': volume_name,
                             'pod': pod_obj,
                             'pvc': pvc_obj,
                             'vlun': hpe3par_vlun,
                             'disk_partition': disk_partition,
                             'pvc_crd': pvc_crd}


def check_volume_in_rcg(volume_name, rcg_name, cli_client):
    flag = False
    rcg_volumes = cli_client.getRemoteCopyGroupVolumes(rcg_name)
    if rcg_volumes is not None:
        for volume in rcg_volumes['members']:
            if volume['localVolumeName'] == volume_name:
                flag = True
                break
    return flag


def check_rcg_exists(rcg_name, cli_client):
    rcg = None
    rcg_list = cli_client.getRemoteCopyGroups()['members']
    for rcg_obj in rcg_list:
        if rcg_obj['name'].startswith(rcg_name):
            rcg = rcg_obj
            break

    return rcg


def get_system_name(cli_client):
    sysinfo = cli_client.getStorageSystemInfo()
    sysname = None
    if sysinfo is not None:
        sysname = sysinfo['name']
    return sysname


def verify_rcopy_target(cli_client, sys_name):
    rcopy_targets = cli_client.getRemoteCopyTargets()
    flag = False
    qw_server_ip = None
    for target in rcopy_targets['members']:
        if target['name'] == sys_name and target['status'] == 3 and target['policies']['mirrorConfig'] == True:
            flag = True
            qw_server_ip = target['quorumIpAddress']
            break

    return flag, qw_server_ip


def get_rcip_ports():
    global PORT_TYPE_RCIP
    rcip_ports = []
    ip_ports = prim_hpe3par_cli.getIPPorts()
    for port in ip_ports:
        logging.getLogger().info(port)
        if port['type'] == PORT_TYPE_RCIP:
            rcip_ports.append(port)


def verify_port_state(ports, port_type=None, state=PORT_STATE_READY):
    state_ready_counter = 0
    port_count = 0
    for port in ports:
        if port_type is not None :
            if port['type'] == port_type:
                port_count += 1
                if port['linkState'] == state:
                    state_ready_counter += 1
        else:
            if port['linkState'] == state:
                state_ready_counter += 1

    if port_type is None:
        port_count = len(ports)
    if state_ready_counter == port_count:
        return True
    else:
        return False


def create_device_info(device_info_yaml):
    # global device_info_yaml
    # device_info_yaml = "%s/replication/device_info_crd.yaml" % globals.yaml_dir
    # Create replication CRD to hold device info
    device_info = manager.create_crd(device_info_yaml, "HPEReplicationDeviceInfo")
    return device_info


def create_sc(sc_yaml):
    ''' global sc_yaml
    sc_yaml = "%s/replication/sc.yaml" % globals.yaml_dir'''
    # Create StorageClass
    sc_obj = manager.create_sc(sc_yaml)
    return sc_obj


def create_statefulset(statefulset_yaml):
    statefulset_obj = manager.create_statefulset(statefulset_yaml)

    # logging.getLogger().info("statefulset_obj :: %s" % statefulset_obj)
    #replica_count = manager.read_value_from_yaml(statefulset_yaml, "StatefulSet", "spec:replicas")
    flag, pvc_obj = manager.check_status(timeout, statefulset_obj.metadata.name, kind='StatefulSet', status='Bound',
                                         namespace=statefulset_obj.metadata.namespace)
    assert flag is True, "StatefulSet %s status check timed out, all replicas not ready..." % pvc_obj.metadata.name

    return statefulset_obj


def create_pvc(pvc_yaml):
    # global pvc_obj, volume_name
    # pvc_yaml = "%s/replication/pvc.yaml" % globals.yaml_dir
    pvc = None
    vol_name = None
    # try:
    # Create Persistent Volume Claim
    pvc = manager.create_pvc(pvc_yaml)

    status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                            namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
    assert status == 'ProvisioningSucceeded', f"{message}"
    logging.getLogger().info("\n\nPVC %s created and came to Bound" % pvc.metadata.name)

    flag, pvc_obj = manager.check_status(timeout, pvc.metadata.name, kind='pvc', status='Bound', namespace=pvc.metadata.namespace)
    assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc.metadata.name
    pvc = pvc_obj
    pvc_crd = manager.get_pvc_crd(pvc.spec.volume_name)
    # print(pvc_crd)
    vol_name = manager.get_pvc_volume(pvc_crd)
    '''except Exception as e:
        logging.getLogger().error("Exception in create/verify pvc :: %s" % e)
        raise e
    finally:'''
    return pvc, vol_name


def create_pod(pod_yaml, volume_name):
    # global pod_obj
    pod = None
    # try:
    # pod_yaml = "%s/replication/pod.yaml" % globals.yaml_dir
    pod = manager.create_pod(pod_yaml)
    flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                         namespace=pod.metadata.namespace)

    assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name
    pod = pod_obj

    # Verify crd fpr published status
    assert manager.verify_pvc_crd_published(volume_name) is True, \
        "PVC CRD %s Published is false after Pod is running" % volume_name
    '''except Exception as e:
        logging.getLogger().error("Exception during create/verify pod :: %s" % e)
        raise e
    finally:'''
    return pod


def verify_vluns(volume_name, pod_obj, pvc_obj):
    iscsi_ips = None
    disk_partition = None
    partition_map = None
    hpe3par_vlun = None
    #try:
    hpe3par_vlun = manager.get_3par_vlun(prim_hpe3par_cli, volume_name)
    '''prim_all_vluns = manager.get_all_vluns(prim_hpe3par_cli, volume_name)
    logging.getLogger().info("vlun on primary array :: \n%s" % hpe3par_vlun)
    logging.getLogger().info("vlun on secondary array :: \n%s" % manager.get_3par_vlun(sec_hpe3par_cli, volume_name))
    '''
    assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
        "Node for pod received from 3par and cluster do not match"

    iscsi_ips = manager.get_iscsi_ips(prim_hpe3par_cli)
    if globals.replication_test:
        iscsi_ips.extend(manager.get_iscsi_ips(sec_hpe3par_cli))
    # logging.getLogger().info("ISCSI IPs from both arrays :: %s" % iscsi_ips)
    logging.getLogger().info("ISCSI IPs :: %s" % iscsi_ips)

    # Read pvc crd again after pod creation. It will have IQN and LunId.
    pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
    flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name, pvc_crd, hpe3par_vlun)
    assert flag is True, "partition not found"
    logging.getLogger().info("disk_partition received are %s " % disk_partition)

    logging.getLogger().info("ISCSI IPs 2:: %s" % iscsi_ips)
    flag, disk_partition_mod, partition_map = manager.verify_multipath(hpe3par_vlun, disk_partition)
    assert flag is True, "multipath check failed"
    logging.getLogger().info("disk_partition after multipath check are %s " % disk_partition)
    logging.getLogger().info("disk_partition_mod after multipath check are %s " % disk_partition_mod)
    logging.getLogger().info("partition_map :: %s" % partition_map)

    # verify if multipath entries count is equal to vlun entries on array
    prim_active_vluns = manager.get_all_active_vluns(prim_hpe3par_cli, volume_name)
    sec_active_vluns = manager.get_all_active_vluns(sec_hpe3par_cli, volume_name)
    logging.getLogger().info("prim_active_vluns :: %s" % prim_active_vluns)
    logging.getLogger().info("sec_active_vluns :: %s" % sec_active_vluns)

    assert len(prim_active_vluns) == len(partition_map['active']), \
        "Multipath entries mismatch on cluster and primary array"
    if globals.replication_test:
        assert len(sec_active_vluns) == len(partition_map['ghost']), \
            "Multipath entries mismatch on cluster and secondary array"

        assert manager.verify_partition(disk_partition_mod), "partition mismatch"
        pass

    assert manager.verify_lsscsi(pod_obj.spec.node_name, disk_partition), "lsscsi verificatio failed"

    logging.getLogger().info("ISCSI IPs 3:: %s" % iscsi_ips)
    '''except Exception as e:
        logging.getLogger().error("Exception while verify_vluns :: %s" % e)
        raise e
    finally:'''
    return iscsi_ips, disk_partition, partition_map, hpe3par_vlun, pvc_crd


def verify_volume_on_arrays(volume_name_on_array, pvc_name):
    # Verify volume created on primary array
    prim_volume = manager.get_volume_from_array(prim_hpe3par_cli, volume_name_on_array)
    assert prim_volume is not None, "Volume is not created on primary array for pvc %s " % pvc_name

    # Verify volume created on secondary array
    sec_volume = manager.get_volume_from_array(prim_hpe3par_cli, volume_name_on_array)
    assert sec_volume is not None, "Volume is not created on secondary array for pvc %s " % pvc_name


def verify_rcg_on_arrays(primary_rcg_name):
    # On array verify if rcg is created and volume is part of rcg
    primary_rcg = prim_hpe3par_cli.getRemoteCopyGroup(primary_rcg_name)
    logging.getLogger().info("RemotecopyGroup :: \n%s" % primary_rcg)

    primary_rcg_flag = verify_rcg(primary_rcg_name, prim_hpe3par_cli, 'primary')
    assert primary_rcg_flag is True, \
        "Remote Copy Groups verification failed on primary array"
    logging.getLogger().info("RemoteCopyGroup %s verification succeeded on primary array" % primary_rcg_name)
    secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
    secondary_rcg_flag = verify_rcg(secondary_rcg_name, sec_hpe3par_cli, 'secondary')
    assert secondary_rcg_flag is True, \
        "Remote Copy Group %s verification failed on secondary array" % secondary_rcg_name


def verify_volume_in_rcgs(volume_name, primary_rcg_name, pvc_name):
    # Verify volume is part of rcg on primary array
    assert check_volume_in_rcg(volume_name, primary_rcg_name, prim_hpe3par_cli) is True, \
        "Failed to add PVC %s to RCG %s on primary" % (pvc_name, primary_rcg_name)
    logging.getLogger().info(
        "Verified PVC %s is part of rcg %s on primary array." % (pvc_name, primary_rcg_name))

    secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)
    # Verify volume is part of rcg on secondary array
    assert check_volume_in_rcg(volume_name, secondary_rcg_name, sec_hpe3par_cli) is True, \
        "Failed to add PVC %s to RCG %s on secondary array" % (pvc_name, secondary_rcg_name)
    logging.getLogger().info(
        "Verified PVC %s is part of rcg %s on secondary array." % (pvc_name, secondary_rcg_name))


def create_verify_obj(device_info_yaml, sc_yaml, pvc_yaml, pod_yaml):
    sc = None
    pvc_obj = None
    pod_obj = None
    primary_rcg_name = None
    secondary_rcg_name = None
    iscsi_ips = None
    disk_partition = None
    partition_map = None
    volume_name = None
    hpe3par_vlun = None

    #try:
    # global sc, sc_yaml, pvc_obj, pod_obj, iscsi_ips, disk_partition, partition_map
    # global device_info_yaml, volume_name, hpe3par_vlun, rcg_name, secondary_rcg_name
    """sec_secret_yaml = "%s/replication/sec_secret.yaml" % globals.yaml_dir
    prim_secret_yaml = "%s/replication/prim_secret.yaml" % globals.yaml_dir"""

    # Create secret for secondary array
    """sec_secret = manager.create_secret(sec_secret_yaml, globals.namespace)
    hpe3par_ip, hpe3par_username, hpe3par_pwd = manager.read_array_prop(sec_secret_yaml)
    sec_hpe3par_cli = manager.get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd)"""

    # Create replication CRD to hold device info
    device_info = create_device_info(device_info_yaml)

    # Create secret for primary array
    """prim_secret = manager.create_secret(prim_secret_yaml, globals.namespace)
    hpe3par_ip, hpe3par_username, hpe3par_pwd = manager.read_array_prop(prim_secret_yaml)
    prim_hpe3par_cli = manager.get_3par_cli_client(hpe3par_ip, hpe3par_username, hpe3par_pwd)"""

    # Create storage class
    sc = create_sc(sc_yaml)

    # Create PVC
    pvc_obj, volume_name = create_pvc(pvc_yaml)

    # Verify volume is created on both arrays
    verify_volume_on_arrays(volume_name, pvc_obj.metadata.name)

    # get rcg name from sc yaml
    primary_rcg_name = manager.read_value_from_yaml(sc_yaml, "StorageClass", "parameters:remoteCopyGroup")

    # Verify if RCG created on both arrays
    verify_rcg_on_arrays(primary_rcg_name)
    secondary_rcg_name = get_secondary_rcg_name(primary_rcg_name, prim_hpe3par_cli)

    # Verify newly created volume is part of rcg on both arrays
    verify_volume_in_rcgs(volume_name, primary_rcg_name, pvc_obj.metadata.name)

    pod_obj = create_pod(pod_yaml, pvc_obj.spec.volume_name)

    # Now verify vluns, multipath and by-path/by-id entries
    iscsi_ips, disk_partition, partition_map, hpe3par_vlun, pvc_crd = verify_vluns(volume_name, pod_obj, pvc_obj)
    logging.getLogger().info("iscsi_ips :: %s" % iscsi_ips)
    '''except Exception as e:
        logging.getLogger().error("Exception while create_verify_obj :: %s" % e)
        raise e
    finally:'''
    return sc, pvc_obj, pod_obj, primary_rcg_name, secondary_rcg_name, iscsi_ips, disk_partition, partition_map, volume_name, hpe3par_vlun, pvc_crd


def verify_pod_deletion(pod_name, pod_namespace, volume_name):
    assert manager.check_if_deleted(timeout, pod_name, "Pod",
                                    namespace=pod_namespace) is True, \
        "Pod %s is not deleted yet " % pod_name
    logging.getLogger().info("Pod is deleted, now verify is published is reset to false in pvc crd...")

    # Verify crd for unpublished status
    time = 0
    timeout_crd = 120
    flag = True
    while True:
        if manager.verify_pvc_crd_published(volume_name) is False:
            break
        if int(time) > int(timeout_crd):
            flag = False
            break
        time += 1
        sleep(1)

    if flag is False:
        logging.getLogger().warning("PVC CRD %s Published is true after Pod is deleted" % volume_name)
    else:
        logging.getLogger().info("PVC CRD %s Published is reset to False after Pod is deleted" % volume_name)


def delete_pod(pod_obj, volume_name):
    # global pod_obj
    assert manager.delete_pod(pod_obj.metadata.name, pod_obj.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                                  pod_obj.metadata.name
    verify_pod_deletion(pod_obj.metadata.name, pod_obj.metadata.namespace, volume_name)


def verify_deleted_vluns(pod_obj, pvc_crd, iscsi_ips, hpe3par_vlun, disk_partition):
    '''logging.getLogger().info("pod_obj, volume_name, iscsi_ips, hpe3par_vlun, disk_partition :: %s, %s, %s, "
                             "%s, %s" % (pod_obj, volume_name, iscsi_ips, hpe3par_vlun, disk_partition))'''
    ''' Execute rescan on worker node - temporary'''
    '''logging.getLogger().info("Rescanning before verifying partition cleanup on worker node %s ..." % pod_obj.spec.node_name)
    command = "rescan-scsi-bus.sh -r -m -f"
    logging.getLogger().info("command is %s " % command)
    rescan_output = manager.get_command_output(pod_obj.spec.node_name, command)'''
    # logging.getLogger().info(rescan_output)

    #pdb.set_trace()
    logging.getLogger().info("Now verify partition cleanup...")
    flag, ip = manager.verify_deleted_partition(iscsi_ips, pod_obj.spec.node_name, hpe3par_vlun, pvc_crd)
    assert flag is True, "Pod %s::volume %s:: partition(s) exists corresponding to iscsi-ip % after " \
                         "unpublish" % (pod_obj.metadata.name, hpe3par_vlun['volumeName'], ip)

    paths = manager.verify_deleted_multipath_entries(pod_obj.spec.node_name, hpe3par_vlun, disk_partition)
    assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

    # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
    flag = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
    logging.getLogger().info("flag after deleted lsscsi verificatio is %s " % flag)
    assert flag, "lsscsi verification failed for vlun deletion"

    prim_active_vluns = manager.get_all_active_vluns(prim_hpe3par_cli, hpe3par_vlun['volumeName'])
    sec_active_vluns = manager.get_all_active_vluns(sec_hpe3par_cli, hpe3par_vlun['volumeName'])
    assert len(prim_active_vluns) == 0, "Active vluns exists on primary array after unpubish"
    assert len(sec_active_vluns) == 0, "Active vluns exists on secondary array after unpubish"


def delete_verify_pvc(pvc, volume_name):
    assert manager.delete_pvc(pvc.metadata.name)

    assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC",
                                    namespace=pvc.metadata.namespace) is True, \
        "PVC %s is not deleted yet " % pvc.metadata.name

    assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
        "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')

    assert manager.verify_delete_volume_on_3par(prim_hpe3par_cli, volume_name), \
        "Volume %s from primary array for PVC %s is not deleted" % (volume_name, pvc.metadata.name)
    assert manager.verify_delete_volume_on_3par(sec_hpe3par_cli, volume_name), \
        "Volume %s from secondary array for PVC %s is not deleted" % (volume_name, pvc.metadata.name)


def delete_verify_sc(sc):
    assert manager.delete_sc(sc.metadata.name) is True

    assert manager.check_if_deleted(timeout, sc.metadata.name, "SC",
                                    sc.metadata.namespace) is True, "SC %s is not deleted yet " \
                                                                    % sc.metadata.name


def delete_verify_device_info(device_info_yaml, rcg_name):
    # Delete replication crd
    manager.hpe_delete_crd(device_info_yaml, "HPEReplicationDeviceInfo")
    # Verify crd for rcg deleted
    assert manager.check_if_crd_deleted(rcg_name, "hpereplicationdeviceinfo") is True, \
        "CRD %s of %s is not deleted yet. Taking longer..." % (rcg_name, 'hpereplicationdeviceinfo')


def delete_verify_obj(device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition, pvc_crd):
    '''global sc, pvc_obj, pod_obj, iscsi_ips, disk_partition
    global device_info_yaml, volume_name, hpe3par_vlun, rcg_name, secondary_rcg_name
    '''
    # delete pod
    delete_pod(pod, pvc.spec.volume_name)

    '''logging.getLogger().info("device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, "
                             "pod, iscsi_ips, hpe3par_vlun, disk_partition :: %s, %s, %s, %s, %s, %s, %s, %s, %s, %s" % (device_info_yaml, volume_name, primary_rcg_name, secondary_rcg_name, sc, pvc, pod, iscsi_ips, hpe3par_vlun, disk_partition))'''
    # verify if vluns and multipath entries are cleared after pod is deleted
    verify_deleted_vluns(pod, pvc_crd, iscsi_ips, hpe3par_vlun, disk_partition)

    # pdb.set_trace()

    # delete pvc and verify if deleted from primary and secondary arrays
    delete_verify_pvc(pvc, volume_name)

    # delete sc and verify
    delete_verify_sc(sc)

    # verify rcg deleted from array
    assert manager.check_if_rcg_exists(primary_rcg_name, prim_hpe3par_cli) is False, \
        "RCG %s is not deleted yet from primary array." % primary_rcg_name
    assert manager.check_if_rcg_exists(secondary_rcg_name, sec_hpe3par_cli) is False, \
        "RCG %s is not deleted yet from secondary array." % secondary_rcg_name
    logging.getLogger().info("RCGs %s,%s are deleted from both arrays." % (primary_rcg_name, secondary_rcg_name))

    # delete replication crd and verify
    delete_verify_device_info(device_info_yaml, primary_rcg_name)
    """
    assert manager.delete_secret(prim_secret.metadata.name, prim_secret.metadata.namespace) is True

    assert manager.check_if_deleted(timeout, prim_secret.metadata.name, "Secret", namespace=prim_secret.metadata.namespace) is True, \
        "Secret %s is not deleted yet " % prim_secret.metadata.name

    assert manager.delete_secret(sec_secret.metadata.name, sec_secret.metadata.namespace) is True

    assert manager.check_if_deleted(timeout, sec_secret.metadata.name, "Secret",
                                    namespace=sec_secret.metadata.namespace) is True, \
        "Secret %s is not deleted yet " % sec_secret.metadata.name
    """


def get_secondary_rcg_name(primary_rcg_name, cli_client):
    secondary_rcg_name = None
    primary_rcg = cli_client.getRemoteCopyGroup(primary_rcg_name)
    # logging.getLogger().info("RemotecopyGroup :: \n%s" % primary_rcg)
    if primary_rcg is not None:
        secondary_rcg_name = primary_rcg['remoteGroupName']

    return secondary_rcg_name


def verify_rcg(rcg_name, cli_client, array_type='primary', action=None):
    status_started_counter = 0
    policy_autoFailover_counter = 0
    policy_pathManagement_counter = 0
    role_validate = False
    rcg = None
    global prim_rcg_group, sec_rcg_group
    logging.getLogger().info("In verify_rcg() for %s" % rcg_name)
    rcg = cli_client.getRemoteCopyGroup(rcg_name)
    logging.getLogger().info("RCG in verify_rcg() :: %s" % rcg)
    if array_type == 'primary':
        if action is None or action == 'stopped':
            if rcg['role'] == 1:
                role_validate = True
        elif action == 'switchover':
            if rcg['role'] == 2:
                role_validate = True
    else:
        if action is None:
            if rcg['role'] == 2:
                role_validate = True
        elif action == 'switchover':
            if rcg['role'] == 1:
                role_validate = True
        elif action == 'recovery':
            logging.getLogger().info("Secondary array::recover::role is %s" % rcg['role'])
        elif action == 'restore':
            logging.getLogger().info("Secondary array::recover::role is %s" % rcg['role'])

    for target in rcg['targets']:
        if 'autoFailover' in target['policies']:
            if target['policies']['autoFailover'] is True or \
                    str(target['policies']['autoFailover']).lower() == 'true':
                policy_autoFailover_counter += 1

        if 'pathManagement' in target['policies']:
            if target['policies']['pathManagement'] is True or \
                    str(target['policies']['pathManagement']).lower() == 'true':
                policy_pathManagement_counter += 1

        logging.getLogger().info("Target after %s :: %s" % (action, target))
        if array_type == 'primary':
            if action == 'failover':
                if target['state'] == 7:
                    status_started_counter += 1
            elif action == 'recovery':
                if target['state'] == 3:
                    status_started_counter += 1
            elif action == 'restore':
                if target['state'] == 3:
                    status_started_counter += 1
            elif action == 'stopped':
                if target['state'] == 5:
                    status_started_counter += 1
            elif action == 'switchover':
                if target['state'] == 3:
                    status_started_counter += 1
            else:
                if target['state'] == 3:
                    status_started_counter += 1
        else:
            if action == 'failover':
                if target['state'] == 5:
                    status_started_counter += 1
            elif action == 'recovery':
                if target['state'] == 3:
                    status_started_counter += 1
            elif action == 'restore':
                if target['state'] == 3:
                    status_started_counter += 1
            elif action == 'stopped':
                if target['state'] == 5:
                    status_started_counter += 1
            elif action == 'switchover':
                if target['state'] == 3:
                    status_started_counter += 1
            else:
                if target['state'] == 3:
                    status_started_counter += 1
    logging.getLogger().info("status_started_counter :: %s" % status_started_counter)
    logging.getLogger().info("policy_autoFailover_counter :: %s" % policy_autoFailover_counter)
    logging.getLogger().info("policy_pathManagement_counter :: %s" % policy_pathManagement_counter)
    if (status_started_counter == len(rcg['targets']) == policy_autoFailover_counter == policy_pathManagement_counter) \
            and role_validate:
        logging.getLogger().info("Policy, status and role verified successfully for rcg %s" % rcg['name'])
        return True
    else:
        return False


def cleanup(sc, pvc, pod):
    global prim_secret, sec_secret
    logging.getLogger().info("====== cleanup :START =========")
    logging.getLogger().info("pod :: %s, pvc :: %s, sc :: %s" % (pod is not None, pvc is not None, sc is not None))
    if pod is not None and pvc is not None and sc is not None:
        logging.getLogger().info("pod :: %s, pvc :: %s, sc :: %s" % (pod.metadata.name, pvc.metadata.name, sc.metadata.name))
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
        """assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')"""
        sleep(5)
        flag = manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos")
        if flag is False:
            logging.getLogger().error("CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos'))
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", sc.metadata.namespace) is False:
        manager.delete_sc(sc.metadata.name)

    logging.getLogger().info("====== cleanup :END =========")


def cleanup_rep_crd(device_info_yaml, rcg_name):
    logging.getLogger().info("cleanup_rep_crd() :: device_info_yaml :: %s, rcg_name :: %s" % (device_info_yaml, rcg_name))
    # Delete replication crd
    manager.hpe_delete_crd(device_info_yaml, "HPEReplicationDeviceInfo")
    '''if rcg_name is not None and manager.verify_crd_exists(rcg_name, "HPEReplicationDeviceInfo"):
        # Delete replication crd
        manager.hpe_delete_crd(device_info_yaml, "HPEReplicationDeviceInfo")
        # Verify crd for rcg deleted
        assert manager.check_if_crd_deleted(prim_rcg_group['name'], "hpereplicationdeviceinfo") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (rcg_name, 'hpereplicationdeviceinfo')'''


def cleanup_statefulset(statefulset):
    logging.getLogger().info("cleanup_statefulset(%s)" % statefulset is not None)
    if statefulset is not None and manager.check_if_deleted(2, statefulset.metadata.name, "StatefulSet",
                                                            statefulset.metadata.namespace) is False:
        manager.delete_statefulset(statefulset.metadata.name, statefulset.metadata.namespace)



