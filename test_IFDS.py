import hpe_3par_kubernetes_manager as manager
from threading import Thread
from time import sleep
import random
import datetime
import logging
import globals

timeout = 900


path_base_yaml = None
access_protocol = None
sc = None
array_secret = None
map_worker_nodes = {}
map_pod_node_dist = {}
map_pvc_volume_name = {}
map_pod_vlun = {}
map_pvc_crd = {}
list_pod_name = []
list_pvc_obj = []
list_pod_obj = []
list_replica_set = []
iscsi_ips = []
disk_partition_map = {}
hpe3par_cli = None
node_to_drain = None
node_to_reboot = None
event = None

# global variable to be shared in thread
pod_status_check_done = False
all_pods_running_time = 0


def test_performance_serial():
    try:
        global node_to_drain
        global pod_status_check_done
        global node_to_reboot
        global event
        global path_base_yaml
        global hpe3par_cli
        global access_protocol

        path_base_yaml = '%s/scale/' % globals.yaml_dir
        path_pvc_yaml = path_base_yaml + 'pvc'
        path_dep_yaml = path_base_yaml + 'dep'
        path_additional_pvc_yaml = path_base_yaml + 'additional_pvc'
        path_additional_dep_yaml = path_base_yaml + 'additional_deps'
        event = 'start'
        logging.getLogger().info("================================= Getting nodes in cluster ==========================================")
        get_nodes_info()

        # populate values from globals
        hpe3par_cli = globals.hpe3par_cli
        access_protocol = globals.access_protocol

        # Create storage class
        create_sc()

        logging.getLogger().info("================================= STEP-1 Creating pvc in bulk ==========================================")
        create_pvc(path_pvc_yaml)

        logging.getLogger().info("================================= STEP-2 Creating deployments in bulk ==========================================")
        create_dep(path_dep_yaml)

        # Populate list of pods from the replicaset list received from reading deployment
        populate_pod_list_from_replicaset()

        # Check if pods are in running state and verify vluns and crd status
        check_pod_status_vlun_crd(deploy_added=True)

        # drain_node('cssosbe01-196114.in.rdlabs.hpecorp.net')
        logging.getLogger().info(map_worker_nodes.keys())
        # get worker 1
        worker_1 = 0
        worker_2 = 1
        node_to_drain = list(map_worker_nodes.keys())[worker_1]
        # cordon all other nodes so that all pods will be mounted on single node only.
        if len(map_worker_nodes.keys()) > 2:
            for node in map_worker_nodes.keys():
                if node is not node_to_drain and node is not list(map_worker_nodes.keys())[worker_2]:
                    corden_node(node)

        logging.getLogger().info("================================= STEP-3 Drain worker 1 %s =======================================" % node_to_drain)
        # drain worker 1
        event = 'drain worker 1'
        drain_node(node_to_drain)
        # Make worker 1 schedulable
        logging.getLogger().info("============================= STEP-4 uncordon worker 1 %s ====================================" % node_to_drain)
        #uncorden_node(node_to_drain)
        # uncordon all nodes now
        for node in map_worker_nodes.keys():
            uncorden_node(node)

        node_to_drain = list(map_worker_nodes.keys())[worker_2]
        # drain worker 2
        logging.getLogger().info("================================= STEP-5 Drain worker 2 %s ======================================" % node_to_drain)
        event = 'drain worker 2'
        drain_node(node_to_drain)

        # Create additional pvc and deployments
        logging.getLogger().info("================================= STEP-6 Creating additonal pvcs and deployments ================================")

        create_pvc(path_additional_pvc_yaml)
        create_dep(path_additional_dep_yaml)
        # Populate list of pods from the replicaset list received from reading deployment
        event = 'added deployment and pvc'
        populate_pod_list_from_replicaset()

        # Check if pods are in running state and verify vluns and crd status
        check_pod_status_vlun_crd(deploy_added=True)

        # Make worker 2 schedulable
        logging.getLogger().info("============================= STEP-7 uncordon worker 2 %s ====================================" % node_to_drain)
        uncorden_node(node_to_drain)

        # Delete some pods
        logging.getLogger().info("================================= STEP-8 Delete few pods ================================")
        event = 'delete pods'
        delete_random_pods()

        # Populate list of pods from the replicaset list received from reading deployment
        populate_pod_list_from_replicaset()

        # Check if pods are in running state and verify vluns and crd status
        check_pod_status_vlun_crd(pod_removed=True)

        # reboot worker 1
        node_to_reboot = list(map_worker_nodes.keys())[worker_1]
        logging.getLogger().info("============================= STEP-9 reboot worker 1 %s ====================================" % node_to_reboot)
        event = 'reboot worker'
        reboot_flag = reboot_node(node_to_reboot)

        # wait before verifying pods
        logging.getLogger().info("========= Sleeping for a min before verification...")
        sleep(60)

        if reboot_flag:
            # Populate list of pods from the replicaset list received from reading deployment
            populate_pod_list_from_replicaset()

            # Check if pods are in running state and verify vluns and crd status
            check_pod_status_vlun_crd()

    finally:
        #cleanup_deployments()
        #cleanup_PVC()
        # Delete all resources and verify if cleanup is done
        # Save vluns for each pvc to verify cleanup after pod deletion

        logging.getLogger().info("================================= Deleting deployments ================================")
        manager.delete_dep_bulk(path_dep_yaml, globals.namespace)
        manager.delete_dep_bulk(path_additional_dep_yaml, globals.namespace)

        # sleep for 2 mins before verification
        logging.getLogger().info("Sleeping for 2 mins before verification of deleted pods...")
        sleep(120)
        verify_pod_deletion_bulk()

        logging.getLogger().info("================================= Deleting PVCs ================================")
        manager.delete_pvc_bulk(path_pvc_yaml, globals.namespace)
        manager.delete_pvc_bulk(path_additional_pvc_yaml, globals.namespace)
        verify_pvc_deletion_bulk()

        logging.getLogger().info("================================= Deleting SC and Secret ================================")
        if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", namespace=sc.metadata.namespace) is False:
            manager.delete_sc(sc.metadata.name)

        # uncordon all nodes
        for node in map_worker_nodes.keys():
            manager.uncorden_node(node)


def delete_random_pods(count=2):
    global list_pod_obj
    try:
        pods_to_delete = random.sample(list_pod_obj, count)
        logging.getLogger().info("Deleting %s pods and will verify they come to running again." % count)
        for pod in pods_to_delete:
            manager.hpe_delete_pod_object_by_name(pod.metadata.name, namespace=pod.metadata.namespace)
    except Exception as e:
        logging.getLogger().error(("Exception in delete_random_pods() :: %s" % e))
        raise e


def reboot_node(node_name):
    flag = True
    try:
        flag = manager.reboot_node(node_name)
    except Exception as e:
        logging.getLogger().error("Exception while rebooting Node %s\n%s" % (node_name, e))
        raise e
    finally:
        return flag


def uncorden_node(node_name):
    try:
        response = manager.uncorden_node(node_name)
        logging.getLogger().info("Node uncorden response is %s" % response)
    except Exception as e:
        logging.getLogger().error(("Exception in uncorden_node :: %s" % e))
        raise e


def corden_node(node_name):
    try:
        response = manager.corden_node(node_name)
        logging.getLogger().info("Node corden response is %s" % response)
    except Exception as e:
        logging.getLogger().error(("Exception in corden_node :: %s" % e))
        raise e


def drain_node(node_name):
    try:
        global list_pod_name
        logging.getLogger().info("================  Draining node %s  ================\n" % node_name)
        response = manager.drain_node(node_name)
        logging.getLogger().info("Node drain response is %s" % response)

        # re-initiate lists
        list_pod_name.clear()
        for key in map_pod_node_dist.keys():
            map_pod_node_dist[key] = []
        populate_pod_list_from_replicaset()
        check_pod_status_vlun_crd()
        verify_vlun_cleanup(node_name=node_name)
    except Exception as e:
        logging.getLogger().error(("Exception in drain_node :: %s" % e))
        raise e


def get_nodes_info():
    global map_pod_node_dist
    try:
        list_nodes = manager.hpe_list_node_objects()

        for node in list_nodes.items:
            if node.spec.unschedulable is None and node.spec.taints is None:
                node_name = node.metadata.name
                """dot_index = node_name.find('.')
                if dot_index > 0:
                    node_name = node_name[0:dot_index]"""
                map_worker_nodes[node_name] = node
                map_pod_node_dist[node_name] = []

        logging.getLogger().info("Worker nodes in cluster are %s" % list(map_worker_nodes.keys()))
    except Exception as e:
        logging.getLogger().error("Exception in test_get_nodes_info :: %s" % e)
        raise e


def create_sc():
    global sc
    global path_base_yaml
    try:
        yml = path_base_yaml + "sc.yml"
        temp_sc = manager.create_sc(yml)
        assert temp_sc is not None, "Storage class is not created."

        # Get accessProtocol from SC
        #array_ip, array_uname, array_pwd, access_protocol = manager.read_array_prop(yml)

        # saving in global for later useage
        sc = temp_sc

    except Exception as e:
        logging.getLogger().info("Exception in test_create_sc :: %s" % e)
        raise e

    finally:
        pass


def create_pvc(yml):
    global list_pvc_obj
    global hpe3par_cli
    global map_pvc_volume_name
    try:
        pvc_map = manager.create_pvc_bulk(yml)
        status_obj_map = manager.check_status_for_bulk('pvc', pvc_map)
        list_pvc_obj.extend(status_obj_map['ProvisioningSucceeded'])
        assert len(status_obj_map['ProvisioningFailed']) == 0, "Some PVC failed to Bound. Terminating test..."
        logging.getLogger().info("PVCs created successfully %s" % list(pvc_map.keys()))

        # logging.getLogger().info(list_pvc_obj)

        # Verify CRD and volume creation on array
        for pvc in list_pvc_obj:
            pvc_crd = manager.get_pvc_crd(pvc.spec.volume_name)
            # logging.getLogger().info(pvc_crd)
            volume_name = manager.get_pvc_volume(pvc_crd)
            volume = manager.get_volume_from_array(hpe3par_cli, volume_name)
            assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name
            # Save volume name for pvc for later usage
            map_pvc_volume_name[pvc.metadata.name] = volume_name
    except Exception as e:
        logging.getLogger().error("Exception in test_create_pvc :: %s" % e)
        raise e
    finally:
        pass


def create_dep(yml):
    try:
        global map_pod_node_dist
        global list_replica_set
        global pod_status_check_done
        global all_pods_running_time
        # Create deployments
        dep_map = manager.create_dep_bulk(yml, globals.namespace)
        #logging.getLogger().info(dep_map)

        # start timer
        pod_status_check_done = False
        thread1 = Thread(target=timer, name="timer")
        thread1.start()

        # List of deployments those are ready
        ready_deps = set()
        # Iterate through deployments to get replica set names
        obj_list = set(dep_map.keys())
        # obj_list = {pod_obj for pod_obj in dep_map.values()}
        while all_pods_running_time < 30 * 60:
            #logging.getLogger().info(f"ready_deps :: {ready_deps}")
            #logging.getLogger().info(f"obj_list :: {obj_list}")
            if ready_deps == obj_list:  # all deps are ready
                pod_status_check_done = True
                break
            else:
                obj_list_to_be_checked = obj_list - ready_deps
                logging.getLogger().info(f"==========\npods to be checked for running status :: {obj_list_to_be_checked}\n")

                for name in obj_list_to_be_checked:
                    #if obj not in ready_deps:
                    #obj = dep_map[name]
                    flag, obj = manager.check_status(5, name, 'deployment', None, globals.namespace)
                    #logging.getLogger().info(obj)
                    #assert flag is True, "Deployment not in desired state, terminating test..."

                    if flag is True:
                        ready_deps.add(name)
                    else:
                        continue
                    condition_list = obj.status.conditions
                    #logging.getLogger().info(f"\n{obj.metadata.name} :: {obj.status}")
                    #logging.getLogger().info(condition_list)

                    for condition in condition_list:
                        if condition.message.startswith('ReplicaSet "%s-' % obj.metadata.name) and \
                                condition.message.endswith('has successfully progressed.'):
                            #logging.getLogger().info(condition.message.split()[1])
                            list_replica_set.append((condition.message.split()[1])[1:-1])

        assert pod_status_check_done is True, f"All Deployments not in desired state in " \
                                              f"{str(datetime.timedelta(0, all_pods_running_time))}, terminating test..."
        logging.getLogger().info(f"======= All pods came to running in {str(datetime.timedelta(0, all_pods_running_time))} ")
        logging.getLogger().info("Deployments created successfully %s" % list(dep_map.keys()))

    except Exception as e:
        logging.getLogger().error("Exception in test_create_dep :: %s" % e)
        raise e

    finally:
        pod_status_check_done = True


def populate_pod_list_from_replicaset():
    global list_replica_set
    global list_pod_name

    logging.getLogger().info("Sleeping for 1 min before refreshing pod list...")
    sleep(60)
    logging.getLogger().info("Over from sleeping...")

    # Get pods in default namespace and match name start with replica set to get corresponding pod.
    list_all_pods = manager.hpe_list_pod_objects_names(namespace=globals.namespace)
    # logging.getLogger().info("All pods in default namespace %s" % list_all_pods)

    # Get pod names
    list_pod_name.clear()
    for replica_set in list_replica_set:
        # logging.getLogger().info([i for i in list_all_pods if i.startswith(replica_set)])
        list_pod_name.extend([i for i in list_all_pods if i.startswith(replica_set)])


def timer():
    global pod_status_check_done
    global all_pods_running_time
    all_pods_running_time = 0
    while pod_status_check_done is False:
        all_pods_running_time += 1
        sleep(1)
        # logging.getLogger().info(".", end='', flush=True)
    # logging.getLogger().info("############ time has time :: %s " % all_pods_running_time)


def check_pod_status_vlun_crd(deploy_added=False, pod_removed=False):
    global list_pod_name
    global map_pod_node_dist
    global map_pod_vlun
    global map_pvc_crd
    global access_protocol
    global disk_partition_map
    global list_pod_obj
    global list_replica_set
    global pod_status_check_done
    global all_pods_running_time

    try:
        iscsi_ips = manager.get_iscsi_ips(globals.hpe3par_cli)
        logging.getLogger().info("Verifying all pods in running state")
        list_pod_obj.clear()
        for node_name in map_pod_node_dist.keys():
            map_pod_node_dist[node_name].clear()

        # Check each pod for status
        pod_status_check_done = False
        thread1 = Thread(target=timer, name="timer")
        thread1.start()

        # List of replica sets those are ready
        ready_replicas = set()
        # Iterate through deployments to get replica set names
        replica_list = set(list_replica_set)
        # obj_list = {pod_obj for pod_obj in dep_map.values()}
        while all_pods_running_time < 30 * 60:
            # logging.getLogger().info(f"ready_deps :: {ready_replicas}")
            # logging.getLogger().info(f"replica_list :: {replica_list}")
            if ready_replicas == replica_list:  # all deps are ready
                pod_status_check_done = True
                break
            else:
                replica_list_to_be_checked = replica_list - ready_replicas
                logging.getLogger().info(f"==========\nReplica sets to be checked if pods are created :: {replica_list_to_be_checked}\n")
                for replica_set_name in replica_list_to_be_checked:
                    replica_has_running_pod = False
                    pods_for_dep = [i for i in list_pod_name if i.startswith(replica_set_name)]
                    logging.getLogger().info("%s has %s list of pods" % (replica_set_name, pods_for_dep))
                    for pod in pods_for_dep:
                        flag, pod_obj = manager.check_status(5, pod, kind='pod', status='Running',
                                                             namespace=globals.namespace)
                        if flag is True:
                            """if deploy_added is False and pod_removed is False:
                                previous_node = map_pod_obj[pod].spec.node_name
                                assert pod_obj.spec.node_name != node_to_reboot and , \
                                    "Pod is still mounted on previous worker node %s " % pod_obj.spec.node_name"""
                            check_mount_node = False
                            if event.startswith('drain'):
                                node_to_match = node_to_drain
                                check_mount_node = True
                            elif event.startswith('reboot'):
                                node_to_match = node_to_reboot
                                check_mount_node = True
                            if check_mount_node is True:
                                """assert pod_obj.spec.node_name != node_to_match, \
                                    "Pod %s is still mounted on previous worker node %s " % (pod, pod_obj.spec.node_name)"""
                                pass
                            replica_has_running_pod = True
                            list_pod_obj.append(pod_obj)
                            ready_replicas.add(replica_set_name)
                            map_pod_node_dist[pod_obj.spec.node_name].append(pod_obj.metadata.name)
                            break
                        else:
                            replica_has_running_pod = False
                    """assert replica_has_running_pod is True, "Deployment %s does not have any pod in running state yet out of %s" % \
                                                            (replica_set_name[0:replica_set_name.index('-')],
                                                             pods_for_dep)"""
                    logging.getLogger().info("Deployment %s has pod in running state" % replica_set_name[0:replica_set_name.index('-')])
        assert pod_status_check_done is True, f"All pods did not come to running in " \
                                              f"{str(datetime.timedelta(0, all_pods_running_time))}, terminating test..."
        logging.getLogger().info("==================================== Time taken to all pods come to running is %s" % str(
            datetime.timedelta(0, all_pods_running_time)))
        logging.getLogger().info("Node wide distribution of pods...")
        for node, pod_list in map_pod_node_dist.items():
            logging.getLogger().info(f"{node} :: {pod_list}\n")

        logging.getLogger().info("Now verifying vlun and CRDs for each pod")
        # Verify CRD and vlun for pods
        for pod_obj in list_pod_obj:
            # logging.getLogger().info(pod_obj)
            # Verify crd fpr published status
            pvc_name = pod_obj.spec.volumes[0].persistent_volume_claim.claim_name
            logging.getLogger().info("\n\nPVC is :: %s " % pvc_name)
            volume_name = manager.hpe_read_pvc_object(pvc_name, globals.namespace).spec.volume_name
            logging.getLogger().info("volume_name is :: %s " % volume_name)
            assert manager.verify_pvc_crd_published(volume_name) is True, \
                "PVC CRD %s Published is false after Pod is running" % volume_name
            logging.getLogger().info("PVC CRD %s published is True" % volume_name)
            pvc_crd = manager.get_pvc_crd(volume_name)
            volume_name = volume_name[0:31]
            hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, volume_name)

            # store vlun for pod in map to be referenced during cleanup verification
            map_pod_vlun[pod_obj.metadata.name] = hpe3par_vlun
            assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
                "Node for pod received from 3par and cluster do not match"
            logging.getLogger().info("Node for pod received from 3par and cluster match")

            # store pvc crd to be referenced during cleanup verification
            map_pvc_crd[pod_obj.metadata.name] = pvc_crd

            flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name, pvc_crd, hpe3par_vlun)
            assert flag is True, "partition not found"
            logging.getLogger().info("disk_partition received are %s " % disk_partition)

            flag, disk_partition_mod, partition_map = manager.verify_multipath(hpe3par_vlun, disk_partition)
            assert flag is True, "multipath check failed"
            logging.getLogger().info("disk_partition after multipath check are %s " % disk_partition)
            logging.getLogger().info("disk_partition_mod after multipath check are %s " % disk_partition_mod)
            assert manager.verify_partition(disk_partition_mod), "partition mismatch"
            logging.getLogger().info("Partition verification done successfully")

            assert manager.verify_lsscsi(pod_obj.spec.node_name, disk_partition), "lsscsi verification failed"
            logging.getLogger().info("lsscsi verification done successfully")
            # save disk_partition to verify cleanup after node drain
            disk_partition_map[pod_obj.metadata.owner_references[0].name] = disk_partition

            pod_node_name = pod_obj.spec.node_name
            logging.getLogger().info("%s is mounted on %s" % (pod_obj.metadata.name, pod_node_name))
            map_pod_node_dist[pod_node_name].append(pod_obj.metadata.name)

        logging.getLogger().info("\n\nSuccessfully verified vlun and CRD status for each pod")
        # logging.getLogger().info("Node wide distribution of pod %s" % map_pod_node_dist)
    except Exception as e:
        logging.getLogger().error("Error in vlun verification :: %s" % e)
        raise e
    finally:
        pod_status_check_done = True


def verify_vlun_cleanup(node_name=None):
    global hpe3par_cli
    global list_pod_obj
    global access_protocol
    global map_pod_vlun
    global map_pvc_crd

    logging.getLogger().info("Now verifying node %s does not have any partitions and multipath entries from previous pods" % node_name)
    for pod_obj in list_pod_obj:
        pod_node = None
        if node_name is None:
            pod_node = pod_obj.spec.node_name
        else:
            pod_node = node_name
        """pvc_name = pod_obj.spec.volumes[0].persistent_volume_claim.claim_name
        logging.getLogger().info("pvc_name :: %s" % pvc_name)
        pvc_obj = manager.hpe_read_pvc_object(pvc_name, globals.namespace)
        logging.getLogger().info("pvc_obj :: %s" % pvc_obj)
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        logging.getLogger().info("pvc_crd :: %s" % pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)
        logging.getLogger().info("volume_name :: %s" % volume_name)
        hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, volume_name)"""
        hpe3par_vlun = map_pod_vlun[pod_obj.metadata.name]
        disk_partition = disk_partition_map[pod_obj.metadata.owner_references[0].name]
        pvc_crd = map_pvc_crd[pod_obj.metadata.name]
        flag, ip = manager.verify_deleted_partition(iscsi_ips, pod_node, hpe3par_vlun, pvc_crd)
        assert flag is True, "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip

        paths = manager.verify_deleted_multipath_entries(pod_node, hpe3par_vlun, disk_partition)
        assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

        # partitions = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
        # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
        flag = manager.verify_deleted_lsscsi_entries(pod_node, disk_partition)
        logging.getLogger().info("flag after deleted lsscsi verificatio is %s " % flag)
        assert flag, "lsscsi verification failed for vlun deletion"


def verify_pod_deletion_bulk():
    timeout = 300
    # Verify if the pods are deleted
    for pod in list_pod_obj:
        assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is True, \
        "Pod %s is not deleted yet " % pod.metadata.name

    verify_vlun_cleanup()


def verify_pvc_deletion_bulk():
    global list_pvc_obj
    global map_pvc_volume_name
    logging.getLogger().info(map_pvc_volume_name)
    timeout = 300
    # Verify if the pods are deleted
    for pvc in list_pvc_obj:
        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')

        assert manager.verify_delete_volume_on_3par(hpe3par_cli, map_pvc_volume_name[pvc.metadata.name]), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (map_pvc_volume_name[pvc.metadata.name], pvc.metadata.name)

    logging.getLogger().info("Verified PVC deletion")


def delete_sc():
    assert manager.delete_sc(sc.metadata.name) is True, f"SC {sc.metadata.name} deletion failed"


def cleanup_deployments():
    try:
        manager.delete_dep_bulk('%s/dep' % globals.yaml_dir)
        manager.delete_dep_bulk('%s/additional_deps' % globals.yaml_dir)
    except Exception as e:
        logging.getLogger().info(f"Exception in deleting deployments {e}")