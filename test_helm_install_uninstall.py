import pytest
from subprocess import call
from time import sleep
import hpe_3par_kubernetes_manager as manager
import logging

import globals

timeout = 900


def helm_uninstall(host_ip, host_name):
    try:
        '''node_obj = manager.hpe_list_node_objects()
        node_list = node_obj.items
        # Fetching master node ip
        for item in node_list:
            if item.spec.taints != "None":
                host_ip = item.status.addresses[0].address
                host_name = item.status.addresses[1].address
            break'''
        host_ip = host_ip
        host_name = host_name

        # ssh to master node and check csi driver installed
        command = "helm ls -n " + globals.namespace
        command_output = manager.get_command_output(host_name, command)
        if len(command_output) == 1:
            logging.getLogger().info("Driver not installed")
            return

        # ssh to master node and execute uninstall commands
        command = "helm uninstall hpe-csi --namespace " + globals.namespace
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        assert command_output[0] == 'release "hpe-csi" uninstalled', "Uninstall of 'hpe-csi' driver failed"
        #sleep(30)

        # Delete crds
        crd_obj = manager.hpe_list_crds()
        for crd in crd_obj:
            manager.hpe_delete_crd(crd)   
            assert manager.check_if_deleted(timeout, crd, kind='Crd',namespace=globals.namespace) is True, \
            "crd %s is not deleted yet " % crd

        # Check plugin pods have been deleted
        pod_obj = manager.hpe_list_pod_objects(globals.namespace)
        pod_list = pod_obj.items
        for item in pod_list:
            if bool(item.metadata.labels):
                if 'app' in item.metadata.labels:
                    if item.metadata.labels['app']=='hpe-csi-controller' or item.metadata.labels['app']=='hpe-csi-node' or item.metadata.labels['app']=='primera3par-csp':
                        assert manager.check_if_deleted(timeout, item.metadata.name, "Pod", namespace=item.metadata.namespace) is True, \
                        "Pod %s is not deleted yet " % pod.metadata.name     
            else:
                continue
        logging.getLogger().info("Plugin pods deleted")        

    except AssertionError as e:
        raise e

    except Exception as e:
        raise e


def test_helm_install():
    try:
        node_obj = manager.hpe_list_node_objects()
        sleep(10)
        node_list = node_obj.items
        # Fetching master node ip
        for item in node_list:
            if item.spec.taints != "None":
                host_ip = item.status.addresses[0].address
                host_name = item.status.addresses[1].address
            break


        # ssh to master node and check csi driver already installed
        command = "helm ls -n " + globals.namespace
        command_output = manager.get_command_output(host_name, command)
        if len(command_output) == 1:
            logging.getLogger().info("Installing driver")
        else:
            logging.getLogger().info("Driver is already installed")
            helm_uninstall(host_ip, host_name)
            #return


        # copy values.yml file to /root dir on master node
        #cmd = "cp INSTALL/values_3par_1.18.yaml values_3par_1.18.yaml"
        cmd = "cp INSTALL/values.yaml values.yaml"
        call(cmd.split(" ")) 

        # ssh to master node and execute adding repo command
        command = "helm repo add hpe https://hpe-storage.github.io/co-deployments"
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        assert command_output[0] == '"hpe" has been added to your repositories', "Install of HPE repo failed"

        # ssh to master node and execute helm repo update command
        command = "helm repo update"
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        assert command_output[1].rfind('Successfully got an update from the "hpe" chart repository') != -1, "Update of HPE repo failed"

        # ssh to master node and execute helm search command for the repo
        command = "helm search repo hpe-csi-driver"
        command_output = manager.get_command_output(host_name, command)
        chart_version = command_output[1].split()[1]
        app_version = command_output[1].split()[2]

        # ssh to master node and install csi driver
        #command = "helm install hpe-csi hpe/hpe-csi-driver --namespace kube-system -f values_3par_1.18.yaml"
        #command = "helm install hpe-csi hpe-csi-driver-1.3.0.tgz --namespace kube-system -f values.yaml"
        command = "helm install hpe-csi hpe/hpe-csi-driver --namespace "+ globals.namespace + " -f values.yaml"
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        #assert command_output[1].rfind('Successfully got an update from the "hpe" chart repository') != -1, "CSI driver installation failed"

        # ssh to master node and check csi driver installation
        #sleep(30)
        command = "helm ls -n "+ globals.namespace
        command_output = manager.get_command_output(host_name, command)
        assert command_output[1].rfind('deployed') != -1, "CSI driver not deployed"
        install_app_version = command_output[1].split()[9]
        installed_chart = command_output[1].split()[8].split("-")[3]
        assert install_app_version == app_version,"app version mismatch: repo vesion {0}, installed version {1}".format(app_version, install_app_version)
        assert installed_chart == chart_version, "chart version mismatch: repo vesion {0}, installed version {1}".format(chart_version, installed_chart)

        # Check plugin pods have been created
        pod_obj = manager.hpe_list_pod_objects(globals.namespace)
        pod_list = pod_obj.items
        for item in pod_list:
            if bool(item.metadata.labels):
                if 'app' in item.metadata.labels:
                    if item.metadata.labels['app']=='hpe-csi-controller' or item.metadata.labels['app']=='hpe-csi-node' or item.metadata.labels['app']=='primera3par-csp':
                        flag, pod_obj = manager.check_status(timeout,item.metadata.name, kind='pod', status='Running', namespace=globals.namespace)
                        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % item.metadata.name
            else:
                continue
   

        # Check crds
        crd_obj = manager.hpe_list_crds()
        assert 'hpenodeinfos.storage.hpe.com' in crd_obj,"node info crd not created"
        assert 'hpevolumeinfos.storage.hpe.com' in crd_obj,"node info crd not created"

    except AssertionError as e:
        raise e

    except Exception as e:
        raise e



def test_helm_install_without_inputfile():
    try:
        #test_helm_uninstall()
        node_obj = manager.hpe_list_node_objects()
        node_list = node_obj.items
        # Fetching master node ip
        for item in node_list:
            if item.spec.taints != "None":
                host_ip = item.status.addresses[0].address
                host_name = item.status.addresses[1].address
            break


        # ssh to master node and check csi driver already installed
        command = "helm ls -n " + globals.namespace
        command_output = manager.get_command_output(host_name, command)
        if len(command_output) == 1:
            logging.getLogger().info("Installing driver")
        else:
            logging.getLogger().info("Driver is already installed")
            helm_uninstall(host_ip, host_name)
            #return


        # ssh to master node and execute adding repo command
        command = "helm repo add hpe https://hpe-storage.github.io/co-deployments"
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        assert command_output[0] == '"hpe" has been added to your repositories', "Install of HPE repo failed"

        # ssh to master node and execute helm repo update command
        command = "helm repo update"
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        assert command_output[1].rfind('Successfully got an update from the "hpe" chart repository') != -1, "Update of HPE repo failed"

        # ssh to master node and execute helm search command for the repo
        command = "helm search repo hpe-csi-driver"
        command_output = manager.get_command_output(host_name, command)
        chart_version = command_output[1].split()[1]
        app_version = command_output[1].split()[2]

        # ssh to master node and install csi driver
        command = "helm install hpe-csi hpe/hpe-csi-driver --namespace " + globals.namespace
        command_output = manager.get_command_output(host_name, command)
        logging.getLogger().info(command_output)
        #assert command_output[1].rfind('Successfully got an update from the "hpe" chart repository') != -1, "CSI driver installation failed"

        # ssh to master node and check csi driver installation
        #sleep(30)
        command = "helm ls -n "+ globals.namespace
        command_output = manager.get_command_output(host_name, command)
        assert command_output[1].rfind('deployed') != -1, "CSI driver not deployed"
        install_app_version = command_output[1].split()[9]
        installed_chart = command_output[1].split()[8].split("-")[3]
        assert install_app_version == app_version,"app version mismatch: repo vesion {0}, installed version {1}".format(app_version, install_app_version)
        assert installed_chart == chart_version, "chart version mismatch: repo vesion {0}, installed version {1}".format(chart_version, installed_chart)

        # Check plugin pods have been created
        pod_obj = manager.hpe_list_pod_objects(globals.namespace)
        pod_list = pod_obj.items
        for item in pod_list:
            if bool(item.metadata.labels):
                if 'app' in item.metadata.labels:
                    if item.metadata.labels['app']=='hpe-csi-controller' or item.metadata.labels['app']=='hpe-csi-node' or item.metadata.labels['app']=='primera3par-csp':
                        flag, pod_obj = manager.check_status(timeout,item.metadata.name, kind='pod', status='Running', namespace=globals.namespace)
                        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % item.metadata.name
            else:
                continue


        # Check crds
        crd_obj = manager.hpe_list_crds()
        assert 'hpenodeinfos.storage.hpe.com' in crd_obj,"node info crd not created"
        assert 'hpevolumeinfos.storage.hpe.com' in crd_obj,"node info crd not created"

    except AssertionError as e:
        raise e

    except Exception as e:
        raise e



