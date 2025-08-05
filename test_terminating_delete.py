"""
Description: This script performs test cases relating to verifying if terminating pods
are deleted during node down when using pod-monitor.
Author: Anupama Vijayaraghavan
Email: anupama.vijayaraghavan@hpe.com
Date Created: 2024-09-18
Version: 1.0
"""

import globals
import hpe_3par_kubernetes_manager as manager
import logging
from time import sleep


timeout = globals.status_check_timeout


def test_terminating_pod_delete_statefulset():
    """
    Functional Test

    To check if CSI monitored pod force-deletes the terminating StatefulSet pod,
    when worker node goes down (through simulated kubelet down).

    Passes if no terminating pods exist on old node,
    and new StatefulSet pod comes to Running state on another worker node.

    """
    logging.getLogger().info("Testrail ID : C60096540")
    sc = None
    statefulset = None
    nodename = None
    try:
        yml = "%s/monitor-terminating-delete.yaml" % globals.yaml_dir
        labels = {"label": "app=monitor-statefulset"}
        # Field for choosing the pods on a particular worker node to search for terminating pods
        fields = {"field": "status.phase=Terminating,spec.nodeName="}

        sc = manager.create_sc(yml)
        statefulset = manager.create_statefulset(yml)

        flag, sts_obj = manager.check_status(
            timeout,
            statefulset.metadata.name,
            kind="StatefulSet",
            status="Ready",
            namespace=statefulset.metadata.namespace,
        )
        assert flag is True, "StatefulSet %s status check timed out, all replicas not ready..." % sts_obj.metadata.name

        # Get pod object so that we can get node of pod to shut down kubelet on
        pod_obj = manager.hpe_list_pod_objects(statefulset.metadata.namespace, **labels)
        nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename of the statefulset pod is %s" % nodename)
        manager.stop_kubelet(nodename)

        logging.getLogger().info("Sleeping for 7 minutes - let node get declared not ready and pods recreate")
        time = 0
        kubelet_timeout = 420
        while True:
            if time % 60 == 0 and time > 0:
                output_status = manager.status_kubelet(nodename)
                logging.getLogger().info("Checking every minute for kubelet status, time :: %s" % time)
                logging.getLogger().info("Kubelet Status on node %s:  %s" % (nodename ,output_status[0]))
                assert output_status[0]  == "Inactive", "Status of kubelet is %s i.e not Inactive (dead)" % output_status[0]
            if int(time) > int(kubelet_timeout):
                break
            time += 1
            sleep(1)
        logging.getLogger().info("Over from sleeping... Starting kubelet back on node %s" % nodename)

        manager.start_kubelet(nodename)
        fields["field"] = fields["field"] + nodename
        logging.getLogger().info("Field selector with nodename: %s" % fields["field"])

        # Assertion for no pods left in terminating state
        # This can fail if other pods on same worker node are in Terminating state
        pod_terminating = manager.hpe_list_pod_objects(statefulset.metadata.namespace, **fields)
        count_pod_terminating = len(pod_terminating.items)
        logging.getLogger().info("Checking terminating pods on node %s: %s" % (nodename, count_pod_terminating))
        assert count_pod_terminating == 0, "There are pods that are in Terminating state on the old worker node"

        # Check that the new pods are running (on another node)
        flag, sts_obj = manager.check_status(
            timeout,
            statefulset.metadata.name,
            kind="StatefulSet",
            status="Ready",
            namespace=statefulset.metadata.namespace,
        )
        assert flag is True, (
            "StatefulSet %s status check timed out, all replicas not ready on new node..." % sts_obj.metadata.name
        )

        pod_obj = manager.hpe_list_pod_objects(statefulset.metadata.namespace, **labels)
        current_nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename after simulating kubelet down is %s" % current_nodename)

        assert (
            current_nodename is not nodename
        ), "The two worker nodes are the same, pod did not recreate on another node"

        assert manager.delete_statefulset(statefulset.metadata.name, statefulset.metadata.namespace)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, (
            "SC %s is not deleted yet " % sc.metadata.name
        )
    except Exception as e:
        logging.getLogger().error("Exception in test_terminating_delete_statefulset :: %s" % e)
        raise e

    finally:
        cleanup(None, sc, None, None, statefulset, None)
        if nodename is not None:
            manager.start_kubelet(nodename)


def test_terminating_deployment_with_pv():
    """

    Functional Test

    To check if CSI monitored pod force-deletes the terminating Deployment pod with PV,
    when worker node goes down (through simulated kubelet down).

    Passes if: no terminating pods exist on old node,
    and new Deployment With PV pod comes to Running state on another worker node.

    """
    logging.getLogger().info("Testrail ID : C60170136")
    sc = None
    pvc = None
    service = None
    deployment = None
    dep_yml = None
    nodename = None
    try:
        yml = "%s/monitor-terminating-delete.yaml" % globals.yaml_dir
        dep_yml = "%s/with-pv-terminating-deployment.yaml" % globals.yaml_dir
        svc_yml = "%s/service-with-pv.yaml" % globals.yaml_dir
        labels = {"label": "app=nginx-with-pv"}
        # Field for choosing the pods on a particular worker node to search for terminating pods
        fields = {"field": "status.phase=Terminating,spec.nodeName="}

        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)

        flag, pvc_obj = manager.check_status(
            timeout, pvc.metadata.name, kind="pvc", status="Bound", namespace=pvc.metadata.namespace
        )
        assert flag is True, "PVC %s status check timed out, not yet in Bound state.." % pvc.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        volume_name = manager.get_pvc_volume(pvc_crd)
        volume = manager.get_volume_from_array(globals.hpe3par_cli, volume_name)
        assert volume is not None, "Volume is not created on 3PAR for pvc %s " % volume_name

        service = manager.create_service(svc_yml)
        deployment = manager.create_dep_bulk(dep_yml, globals.namespace)

        # Getting deployment object as only one deployment is created
        dep = [elem for elem in deployment.values()]
        flag, dep_obj = manager.check_status(
            timeout, dep[0].metadata.name, kind="deployment", status="Ready", namespace=dep[0].metadata.namespace
        )
        assert flag is True, "Deployment %s status check timed out, all replicas not ready..." % dep[0].metadata.name

        # Get pod object so that we can get node of pod to shut down kubelet on
        pod_obj = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **labels)
        nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename of the deployment pod is %s" % nodename)
        manager.stop_kubelet(nodename)

        # Simulate the node down
        logging.getLogger().info("Sleeping for 7 minutes - let node get declared not ready and pods recreate")
        time = 0
        kubelet_timeout = 420
        while True:
            if time % 60 == 0 and time > 0:
                output_status = manager.status_kubelet(nodename)
                logging.getLogger().info("Checking every minute for kubelet status, time :: %s" % time)
                logging.getLogger().info("Kubelet Status on node %s:  %s" % (nodename ,output_status[0]))
                assert output_status[0]  == "Inactive", "Status of kubelet is %s i.e not Inactive (dead)" % output_status[0]
            if int(time) > int(kubelet_timeout):
                break
            time += 1
            sleep(1)

        logging.getLogger().info("Over from sleeping... Starting kubelet back on node %s" % nodename)
        manager.start_kubelet(nodename)

        fields["field"] = fields["field"] + nodename
        logging.getLogger().info("Field selector with nodename: %s" % fields["field"])

        # Assertion for no pods left in terminating state
        # This can fail if other pods on same worker node are in Terminating state
        pod_terminating = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **fields)
        count_pod_terminating = len(pod_terminating.items)
        logging.getLogger().info("Checking terminating pods on node %s: %s" % (nodename, count_pod_terminating))
        assert count_pod_terminating == 0, "There are pods that are in Terminating state on the old worker node"

        # Check that the new pods are running (on another node)
        flag, dep_obj = manager.check_status(
            timeout, dep[0].metadata.name, kind="deployment", status="Ready", namespace=dep[0].metadata.namespace
        )
        assert flag is True, (
            "Deployment %s status check timed out, all replicas not ready on new node..." % dep[0].metadata.name
        )

        pod_obj = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **labels)
        current_nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename after simulating kubelet down is %s" % current_nodename)

        assert (
            current_nodename is not nodename
        ), "The two worker nodes are the same, pod did not recreate on another node"

        manager.delete_dep_bulk(dep_yml, globals.namespace)

        assert (
            manager.check_if_deleted(2, dep[0].metadata.name, "Deploy", namespace=dep[0].metadata.namespace) is True
        ), ("Deployment %s is not deleted yet..." % dep[0].metadata.name)

        # If deployment was deleted, set dep_yml to None so that cleanup doesn't happen twice
        dep_yml = None

        assert manager.delete_service(service.metadata.name, service.metadata.namespace) is True

        assert (
            manager.check_if_deleted(2, service.metadata.name, "Service", namespace=service.metadata.namespace) is True
        ), ("Service %s is not deleted yet " % service.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, (
            "SC %s is not deleted yet " % sc.metadata.name
        )
    except Exception as e:
        logging.getLogger().error("Exception in test_terminating_deployment_with_pv :: %s" % e)
        raise e

    finally:
        if dep_yml is not None:
            cleanup(None, None, None, None, None, dep_yml)
        cleanup(None, sc, pvc, service, None, None)
        if nodename is not None:
            manager.start_kubelet(nodename)


def test_terminating_deployment_without_pv():
    """

    Functional Test

    To check if CSI force-deletes the deployment without pv terminating pod,
    when worker node goes down (through simulated kubelet down).

    Passes if: no terminating pods exist on old node,
    and new Deployment without PV pod comes to Running state on another worker node.

    """
    logging.getLogger().info("Testrail ID : C60170137")
    sc = None
    service = None
    deployment = None
    dep_yml = None
    nodename = None
    try:
        yml = "%s/monitor-terminating-delete.yaml" % globals.yaml_dir
        dep_yml = "%s/without-pv-terminating-deployment.yaml" % globals.yaml_dir
        svc_yml = "%s/service-without-pv.yaml" % globals.yaml_dir
        labels = {"label": "app=nginx-without-pv"}
        # Field for choosing the pods on a particular worker node to search for terminating pods
        fields = {"field": "status.phase=Terminating,spec.nodeName="}

        sc = manager.create_sc(yml)
        service = manager.create_service(svc_yml)
        deployment = manager.create_dep_bulk(dep_yml, globals.namespace)

        # Getting deployment object as only 1 deployment is created
        dep = [elem for elem in deployment.values()]

        flag, dep_obj = manager.check_status(
            timeout, dep[0].metadata.name, kind="deployment", status="Ready", namespace=dep[0].metadata.namespace
        )
        assert flag is True, "Deployment %s status check timed out, all replicas not ready..." % dep[0].metadata.name

        # Get pod object so that we can get node of pod to shut down kubelet on
        pod_obj = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **labels)
        nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename of the deployment without pv pod is %s" % nodename)
        manager.stop_kubelet(nodename)

        # Simulate the node down
        logging.getLogger().info("Sleeping for 7 minutes - let node get declared not ready and pods recreate")
        time = 0
        kubelet_timeout = 420
        while True:
            if time % 60 == 0 and time > 0:
                output_status = manager.status_kubelet(nodename)
                logging.getLogger().info("Checking every minute for kubelet status, time :: %s" % time)
                logging.getLogger().info("Kubelet Status on node %s:  %s" % (nodename ,output_status[0]))
                assert output_status[0]  == "Inactive", "Status of kubelet is %s i.e not Inactive (dead)" % output_status[0]
            if int(time) > int(kubelet_timeout):
                break
            time += 1
            sleep(1)

        logging.getLogger().info("Over from sleeping... Starting kubelet back on node %s" % nodename)
        manager.start_kubelet(nodename)

        fields["field"] = fields["field"] + nodename
        logging.getLogger().info("Field selector with nodename: %s" % fields["field"])

        # Assertion for no pods left in terminating state
        # This can fail if other pods on same worker node are in Terminating state
        pod_terminating = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **fields)
        count_pod_terminating = len(pod_terminating.items)
        logging.getLogger().info("Checking terminating pods on node %s: %s" % (nodename, count_pod_terminating))
        assert count_pod_terminating == 0, "There are pods that are in Terminating state on the old worker node"

        # Check that the new pods are running (on another node)
        flag, dep_obj = manager.check_status(
            timeout, dep[0].metadata.name, kind="deployment", status="Ready", namespace=dep[0].metadata.namespace
        )
        assert flag is True, (
            "Deployment %s status check timed out, all replicas not ready on new node..." % dep[0].metadata.name
        )

        pod_obj = manager.hpe_list_pod_objects(dep[0].metadata.namespace, **labels)
        current_nodename = pod_obj.items[0].spec.node_name
        logging.getLogger().info("Nodename after simulating kubelet down is %s" % current_nodename)

        assert (
            current_nodename is not nodename
        ), "The two worker nodes are the same, pod did not recreate on another node"

        manager.delete_dep_bulk(dep_yml, globals.namespace)

        assert (
            manager.check_if_deleted(2, dep[0].metadata.name, "Deploy", namespace=dep[0].metadata.namespace) is True
        ), ("Deployment %s is not deleted yet..." % dep[0].metadata.name)

        # If deployment was deleted, set dep_yml to None so that cleanup doesn't happen twice
        dep_yml = None

        assert manager.delete_service(service.metadata.name, service.metadata.namespace) is True

        assert (
            manager.check_if_deleted(2, service.metadata.name, "Service", namespace=service.metadata.namespace) is True
        ), ("Service %s is not deleted yet " % service.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC", sc.metadata.namespace) is True, (
            "SC %s is not deleted yet " % sc.metadata.name
        )
    except Exception as e:
        logging.getLogger().error("Exception in test_terminating_deployment_without_pv :: %s" % e)
        raise e

    finally:
        if dep_yml is not None:
            cleanup(None, None, None, None, None, dep_yml)
        cleanup(None, sc, None, service, None, None)
        if nodename is not None:
            manager.start_kubelet(nodename)


def cleanup(secret, sc, pvc, svc, statefulset, deployment):
    logging.getLogger().info("====== cleanup :START =========")
    if (
        statefulset is not None
        and manager.check_if_deleted(
            2, statefulset.metadata.name, "StatefulSet", namespace=statefulset.metadata.namespace
        )
        is False
    ):
        manager.delete_statefulset(statefulset.metadata.name, statefulset.metadata.namespace)
    if deployment is not None:
        logging.getLogger().info("Deleting deployment...")
        manager.delete_dep_bulk(deployment, globals.namespace)
    if (
        svc is not None
        and manager.check_if_deleted(2, svc.metadata.name, "Service", namespace=svc.metadata.namespace) is False
    ):
        assert manager.delete_service(svc.metadata.name, svc.metadata.namespace)
    if (
        pvc is not None
        and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False
    ):
        manager.delete_pvc(pvc.metadata.name)
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", namespace=sc.metadata.namespace) is False:
        manager.delete_sc(sc.metadata.name)
    logging.getLogger().info("====== cleanup :END =========")
