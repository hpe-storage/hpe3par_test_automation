from os import path
from time import sleep
import yaml

from kubernetes import client, config
from hpe3parclient.client import HPE3ParClient
import paramiko

import docker
from docker.utils import kwargs_from_env
import os
import utils


config.load_kube_config()
k8s_storage_v1 = client.StorageV1Api()
k8s_core_v1 = client.CoreV1Api()
k8s_apps_v1 = client.ExtensionsV1beta1Api()
k8s_apps_v2 = client.AppsV1beta1Api()
secret_exists = False
TEST_API_VERSION = os.environ.get('DOCKER_TEST_API_VERSION')

class KubernetesAutomationTest:
    '''def hpe_create_sc_object(self,yml):
        try:
            with open(yml) as f:
                dep = yaml.safe_load(f)
                print("Storage class YAML :: %s" % dep)
                resp = k8s_storage_v1.create_storage_class(body=dep)
                print("Storage Class created. status=%s" % resp.metadata.name)
                #print("Storage class creation response :: %s" % resp)
                return resp
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e'''

    def hpe_create_sc_object(self,yml):
        try:
            resp = k8s_storage_v1.create_storage_class(yml)
            print("Storage Class created. status=%s" % resp.metadata.name)
            #print("Storage class creation response :: %s" % resp)
            return resp
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e


    def hpe_list_deployment_objects(self):
        try:
            dep_list = k8s_apps_v2.list_namespaced_deployment(namespace="default")
            return dep_list
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_deployment_objects_names(self):
        try:
            dep_names = []
            dep_list = self.hpe_list_deployment_objects()
            for dep in dep_list.items:
                dep_names.append(dep.metadata.name)

            return dep_names
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e


    def hpe_read_sc_object(self,sc_name):
        try:
            SC = k8s_storage_v1.read_storage_class(sc_name)
            return SC
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_read_deployment_status(self,dep_name):
        try:
            dep_status = k8s_apps_v2.read_namespaced_deployment_status(dep_name, namespace="default")
            return dep_status
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e


    def hpe_verify_storage_class(self,file,sc_obj):
        areEqual = True
        with open(file) as f:
            yml = yaml.safe_load(f)
            properties = ['allow_volume_expansion','allowed_topologies','kind','mount_options','provisioner']
            metadata_properties = ['annotations','labels','managed_fields','name','namespace']
            for property in properties:
                #hpe_verify_property('allow_volume_expansion',yml,sc_obj)
                if not self.hpe_verify_property(property,yml,sc_obj):
                    areEqual = False
                    break
            """ print("allow_volume_expansion from yml :: " % yml.get('allow_volume_expansion'))
            if "allow_volume_expansion" in yml:
                if(yml.get('allow_volume_expansion')!=sc_obj.allow_volume_expansion):
                    areEqual = False
            else:
                if(sc_obj.allow_volume_expansion!='None'):
                    areEqual = False """
        return areEqual

    def hpe_verify_property(self,property_name,dict,obj):
        #print("Verifying %s " % property_name)
        if property_name in dict:
            #print("%s is in yaml and value in object %s" % (property_name, self.hpe_get_value_from_object(obj,property_name)))
            #print("YAML Value :: %s"%dict.get(property_name))
            #print("Object Value %s "%self.hpe_get_value_from_object(obj,property_name))
            return dict.get(property_name)==self.hpe_get_value_from_object(obj,property_name)
        else:
            #print("Property not in YAML")
            prop_val = self.hpe_get_value_from_object(obj,property_name)
            #print("Value from object :: %s " % prop_val)
            if(str(prop_val)=='None'):
                #print("Returning True, since property neither set in yaml nor in object")
                return True
            else:
                #print("Returning False, since property set in object but not in yaml")
                return False
            """ switcher = { 'None': True }
            print("Value from object :: %s " % self.hpe_get_value_from_object(obj,property_name))
            return switcher.get(self.hpe_get_value_from_object(obj,property_name), False)"""

    def hpe_get_value_from_object(self,obj,property_name):
        switcher = {
            'allow_volume_expansion': obj.allow_volume_expansion,
            'allowed_topologies': obj.allowed_topologies,
            'kind': obj.kind,
            'mount_options': obj.mount_options,
            'provisioner': obj.provisioner,
            'reclaim_policy': obj.reclaim_policy,
            'volume_binding_mode': obj.volume_binding_mode
            }
        return switcher.get(property_name)

    def hpe_create_pv_object(self,yml):
        try:
            #with open(yml) as f:
            #   dep = yaml.safe_load(f)
            #print("Type of dep is :: %s " % type(yml))
            #print("PV YAML :: %s" % yml)
            pv = k8s_core_v1.create_persistent_volume(body=yml)
            # print("PV created. status=%s" % pv.status.phase)
            # print("PV creation response :: %s" % pv)
            return pv
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_create_pod_object(self,yml):
        try:
            #with open(yml) as f:
            #    dep = yaml.safe_load(f)
            #print("pod YAML :: %s" % yml)
            pod = k8s_core_v1.create_namespaced_pod(namespace="default", body=yml)
            # print("pod created. status=%s" % pod.status.phase)
            # print("PVC creation response :: %s" % pvc)
            return pod
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_create_pvc_object(self,yml):
        try:
            #with open(yml) as f:
            #    dep = yaml.safe_load(f)
            #print("Type of dep is :: %s " % type(yml))
            #print("PVC YAML :: %s" % yml)
            pvc = k8s_core_v1.create_namespaced_persistent_volume_claim(namespace="default", body=yml)
            # print("PVC created. status=%s" % pvc.status.phase)
            # print("PVC creation response :: %s" % pvc)
            return pvc
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_verify_pvc_list(self, sleep_interval):
        try:
            pvc_flag = True
            sleep(sleep_interval)
            pvc_list = k8s_core_v1.list_namespaced_persistent_volume_claim(namespace="default")
            #print("List of PVCs :: %s" % pvc_list)
            for pvc in pvc_list.items:
                print("%s status is %s "% (str(pvc.metadata.name),str(pvc.status.phase)))
                if str(pvc.status.phase) != "Bound":
                    print("PVC %s is created but not bound " % str(pvc.metadata.name))
                    pvc_flag = False
                    break
            return pvc_flag
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_get_pvc_list(self):
        try:
            return k8s_core_v1.list_namespaced_persistent_volume_claim(namespace="default")
        except Exception as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_delete_sc_object(self,yml):
        try:
            sc_name=""
            with open(yml) as f:
                dep = yaml.safe_load_all(f)
                for el in dep:
                    print("Type of el is :: %s " % type(el))
                    if str(el.get('kind')) == "StorageClass":
                        sc_name=el['metadata']['name']
                        resp = k8s_storage_v1.delete_storage_class(sc_name)
                        print("Storage class deletion response :: '%s'" % resp)
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_delete_pvc_object_by_yaml(self,yml):
        try:
            pvc_name=""
            with open(yml) as f:
                dep = yaml.safe_load(f)
                pvc_name=dep.get('metadata').get('name')
                pvc = k8s_core_v1.delete_namespaced_persistent_volume_claim(pvc_name, namespace="default")
                #print("PVC deleted. status='%s'" % pvc.metadata.name)
                print("PVC deletion response :: '%s'" % pvc)
                sleep(1)
                #assertEqual(pvc.status,'Bound')

        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_delete_pvc_object_by_name(self,pvc_name):
        try:
            pvc = k8s_core_v1.delete_namespaced_persistent_volume_claim(pvc_name, namespace="default")
            #print("PVC deleted. status='%s'" % pvc.metadata.name)
            # print("PVC deletion response :: '%s'" % pvc)
            sleep(1)
            #assertEqual(pvc.status,'Bound')
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_create_deployment(self, yml):
        try:
            dep = ""
            object = ""
            global secret_exists
            with open(yml) as f:
                lst = list(yaml.safe_load_all(f))
                print("Full YAML :: %s " % lst)
                for el in lst:
                    print("Type of el is :: %s " % type(el))
                    if str(el.get('kind')) == "Deployment":
                        print("deployment YAML :: %s" % el)
                        object = k8s_apps_v2.create_namespaced_deployment(namespace="default", body=el)
                        print("|||||||||| DEPLOYMENT created  ::  %s " % object)
                    if str(el.get('kind')) == "Secret":
                        print("Secret YAML :: %s " % el)
                        if not secret_exists:
                            object = k8s_core_v1.create_namespaced_secret(namespace="default", body=el)
                            print("Deployment created  ::  %s " % object)
                            secret_exists = True
            return object
                #print("Deployment creation response :: %s" % pod)
                #print("Deployment created. status=%s" % pod.status.phase)

        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_read_deployment(self, yml):
        try:
            dep = ""
            object = ""
            with open(yml) as f:
                lst = list(yaml.safe_load_all(f))
                print("Full YAML :: %s " % lst)
                for el in lst:
                    print("Type of el is :: %s " % type(el))
                    if str(el.get('kind')) == "Deployment":
                        print("deployment YAML :: %s" % el)
                        dep_name = el['metadata']['name']
                        object = k8s_apps_v1.read_namespaced_deployment(namespace="default", name=dep_name)
                        print("|||||||||| DEPLOYMENT created  ::  %s " % object)
            return object

        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e


    def hpe_verify_pod_list(self, sleep_interval):
        try:
            pod_flag = True
            sleep(sleep_interval)
            pod_list = k8s_core_v1.list_namespaced_pod(namespace="default")
            #print("List of Pods :: %s" % pod_list)
            for pod in pod_list.items:
                print("%s status is %s "% (str(pod.metadata.name),str(pod.status.phase)))
                if str(pod.status.phase) != "Running":
                    print("Pod %s is created but not running " % str(pod.metadata.name))
                    pod_flag = False
                    break
            return pod_flag
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_get_pod_list(self):
        try:
            return k8s_core_v1.list_namespaced_pod(namespace="default")
        except Exception as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_get_pod(self, pod_name):
        try:
            return k8s_core_v1.read_namespaced_pod(pod_name,namespace="default")
        except Exception as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_delete_deploymente(self, yml):
        try:
            object = ""
            with open(yml) as f:
                lst = list(yaml.safe_load_all(f))
                print("Full YAML :: %s " % lst)
                for el in lst:
                    print("Type of el is :: %s " % type(el))
                    if str(el.get('kind')) == "Deployment":
                        print("deployment YAML :: %s" % el)
                        dep_name = el['metadata']['name']
                        body = client.V1DeleteOptions(propagation_policy='Background')
                        object = k8s_apps_v2.delete_namespaced_deployment(namespace='default', name=dep_name, body=body)
                        #, body=el)
                        print("deleted object  ::  %s " % object)
                    if str(el.get('kind')) == "Secret":
                        print("Secret YAML :: %s " % el)
                        secret_name = el['metadata']['name']

                        object = k8s_core_v1.delete_namespaced_secret(namespace="default", name=secret_name)
                        print("Deployment created  ::  %s " % object)
                #print("Deployment creation response :: %s" % pod)
                #print("Deployment created. status=%s" % pod.status.phase)
                return object
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_verify_lun(self, node_name):
        print("========= Verifying lun for %s ==========" % node_name)
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=node_name)
            # get lscsi output
            stdin,stdout,stderr=ssh_client.exec_command('lsscsi')
            print("stdout :: %s " % stdout.read())
            lsscsi_output = stdout.read()
            print("------------ %s :: lscsi ---------- \n%s"% (node_name,lsscsi_output))

            # get multipath -ll
            stdin, stdout, stderr = ssh_client.exec_command('multipath -ll')
            multipath_output = stdout.read()
            print("------------ %s :: multipath -ll ---------- \n%s" % (node_name,multipath_output))

            # get ls -lrth /dev/disk/by-path
            stdin, stdout, stderr = ssh_client.exec_command('ls -lrth /dev/disk/by-path')
            ls_output = stdout.read()
            print("------------ %s :: ls -lrth /dev/disk/by-path ---------- \n%s" % (node_name,ls_output))

            #print("stdin :: " % stdin.readlines())
            print("stderr :: " % stderr.read())
        except Exception as e:
            print("Exception while ssh %s " % e)

        return True

    def _hpe_get_3par_client_login(self, HPE3PAR_API_URL, HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD):
        # Login to 3Par array and initialize connection for WSAPI calls
        hpe_3par_cli = HPE3ParClient(HPE3PAR_API_URL, True, False, None, True)
        hpe_3par_cli.login(HPE3PAR_USERNAME, HPE3PAR_PWD)
        hpe_3par_cli.setSSHOptions(HPE3PAR_IP, HPE3PAR_USERNAME, HPE3PAR_PWD)
        return hpe_3par_cli

    def check_status(self, timeout, name, kind, status):
        time = 0
        flag = True
        # print("timeout :: %s" % timeout)
        # print("time :: %s" % time)
        # print("kind :: %s" % kind)
        # print("status :: %s" % status)

        while True:
            obj = ""
            if kind == 'pv':
                obj = k8s_core_v1.read_persistent_volume(name)
            elif kind == 'pvc':
                obj = k8s_core_v1.read_namespaced_persistent_volume_claim(name, namespace="default")
            elif kind == 'pod':
                obj = k8s_core_v1.read_namespaced_pod(name, namespace="default")
            elif kind == 'deployment':
                obj = k8s_apps_v2.read_namespaced_deployment_status(name, namespace="default")

            else:
                print("Not a supported kind")
                flag = False
                break
            # print("obj.status.phase :: %s" % obj.status.phase)
            #print ".",
            if kind == 'pv' or kind == 'pvc' or kind == 'pod':
                if obj.status.phase == status:
                    break
            elif kind == 'deployment':
                if obj.status.available_replicas == status:
                    break
            elif int(time) > int(timeout):
                print("\n%s not yet in %s state. Taking longer than expected..." % (kind, status))
                # print("obj :: %s" % obj)
                flag = False
                break
            time += 1
            sleep(1)

        return flag

    def get_pvc_obj(self, name):
        return k8s_core_v1.read_namespaced_persistent_volume_claim(name, namespace="default")

    def get_docker_client(self):
        return docker.APIClient(
            version=TEST_API_VERSION, timeout=60, **kwargs_from_env()
        )

    def get_command_output(self, node_name, command):
        try:
            # print("Executing command...")
            ssh_client = paramiko.SSHClient()
            # print("ssh client %s " % ssh_client)
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # print("host key set")
            # print("node_name = %s, command = %s " % (node_name, command))
            ssh_client.connect(hostname=node_name)
            #ssh_client.connect(node_name, username='vagrant', password='vagrant', key_filename='/home/vagrant/.ssh/id_rsa')
            # ssh_client.connect(node_name, username='vagrant', password='vagrant', look_for_keys=False, allow_agent=False)
            # print("connected...")
            # execute command and get output
            stdin,stdout,stderr=ssh_client.exec_command(command)
            # print("stdout :: %s " % stdout.read())
            command_output = []
            while True:
                line = stdout.readline()
                if not line:
                    break
                command_output.append(str(line).strip())
                print(line)
            # command_output = stdout.read()

            # print("stdin :: " % stdin.readlines())
            # print("stderr :: %s" % stderr.read())
            ssh_client.close()

            return command_output
        except Exception as e:
            print("Exception while ssh %s " % e)

    def hpe_delete_pod_object(self,pod_name):
        try:
            pod = k8s_core_v1.delete_namespaced_pod(pod_name, namespace="default")
            #print("PVC deleted. status='%s'" % pvc.metadata.name)
            # print("POD deletion response :: '%s'" % pod)
            sleep(1)
            #assertEqual(pvc.status,'Bound')
        except client.rest.ApiException as e:
             print("Exception :: %s" % e)
             raise e

    def hpe_delete_pv_object_by_name(self,pv_name):
        try:
            pv = k8s_core_v1.delete_persistent_volume(pv_name)
            # print("PVC deleted. status='%s'" % pvc.metadata.name)
            # print("PV deletion response :: '%s'" % pv)
            sleep(1)
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_read_pod_object(self,pod_name):
        try:
            pod = k8s_core_v1.read_namespaced_pod(pod_name, namespace="default")
            return pod
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_read_pvc_object(self,pvc_name):
        try:
            pvc = k8s_core_v1.read_namespaced_persistent_volume_claim(pvc_name, namespace="default")
            return pvc
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_read_pv_object(self,pv_name):
        try:
            pv = k8s_core_v1.read_persistent_volume(pv_name)
            return pv
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pod_objects(self):
        try:
            pod_list = k8s_core_v1.list_namespaced_pod(namespace="default")
            return pod_list
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pod_objects_names(self):
        try:
            pod_names = []
            pod_list = self.hpe_list_pod_objects()
            for pod in pod_list.items:
                pod_names.append(pod.metadata.name)

            return pod_names
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pvc_objects(self):
        try:
            pvc_list = k8s_core_v1.list_namespaced_persistent_volume_claim(namespace="default")
            return pvc_list
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pvc_objects_names(self):
        try:
            pvc_names = []
            pvc_list = self.hpe_list_pvc_objects()
            for pvc in pvc_list.items:
                pvc_names.append(pvc.metadata.name)

            return pvc_names
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pv_objects(self):
        try:
            pv_list = k8s_core_v1.list_persistent_volume()
            return pv_list
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def hpe_list_pv_objects_names(self):
        try:
            pv_names = []
            pv_list = self.hpe_list_pv_objects()
            for pv in pv_list.items:
                pv_names.append(pv.metadata.name)

            return pv_names
        except client.rest.ApiException as e:
            print("Exception :: %s" % e)
            raise e

    def check_if_deleted(self, timeout, name, kind):
        time = 0
        flag = True

        # print("timeout :: %s" % timeout)
        # print("name :: %s" % name)
        # print("kind :: %s" % kind)

        while True:
            if kind == 'pv':
                obj_list = self.hpe_list_pv_objects_names()
            elif kind == 'pvc':
                obj_list = self.hpe_list_pvc_objects_names()
            elif kind == 'pod':
                obj_list = self.hpe_list_pod_objects_names()
            elif kind == 'volume':
                obj_list = self.get_docker_client().volumes()
            else:
                print("Not a supported kind")
                flag = False
                break
            # print(obj_list)
            if name not in obj_list:
                break

            if int(time) > int(timeout):
                print("\n%s not yet deleted. Taking longer than expected..." % kind)
                flag = False
                break
            time += 1
            sleep(1)

        return flag

    def verify_volume_on_3par(self, hpe3par_volume, backend_volume_name, backend_volume_id, docker_volume_name, vvs_name=None, **kwargs):
        hpe3par_cli = self._hpe_get_3par_client_login(kwargs["HPE3PAR_API_URL"], kwargs["HPE3PAR_IP"],
                                                      kwargs["HPE3PAR_USERNAME"], kwargs["HPE3PAR_PWD"])
        # Loop to wait for completion of cloning
        count = 0
        while hpe3par_volume['copyType'] == 2 and count < 60:
            hpe3par_volume = hpe3par_cli.getVolume(backend_volume_name)
            count = count + 1
            sleep(10)

        # Verify volume and its properties in 3Par array
        assert hpe3par_volume['name'], backend_volume_name
        assert hpe3par_volume['copyType'], 1
        assert hpe3par_volume['state'], 1
        if 'size' in kwargs:
            assert hpe3par_volume['sizeMiB'], int(kwargs['size']) * 1024
        else:
            assert hpe3par_volume['sizeMiB'], 102400
        if 'provisioning' in kwargs:
            if kwargs['provisioning'] == 'full':
                assert hpe3par_volume['provisioningType'], 1
            elif kwargs['provisioning'] == 'thin':
                assert hpe3par_volume['provisioningType'], 2
            elif kwargs['provisioning'] == 'dedup':
                assert hpe3par_volume['provisioningType'], 6
                assert hpe3par_volume['deduplicationState'], 1
        else:
            assert hpe3par_volume['provisioningType'], 2
        if 'flash_cache' in kwargs:
            if vvs_name:
                vvset = hpe3par_cli.getVolumeSet(vvs_name)
                # Ensure flash-cache-policy is set on the vvset
                assert vvset['flashCachePolicy'], 1
                # Ensure the created volume is a member of the vvset
                assert backend_volume_name, [vv_name for vv_name in vvset['setmembers']]

            elif kwargs['flash_cache'] == 'true':
                vvset_name = utils.get_3par_vvset_name(backend_volume_id)
                vvset = hpe3par_cli.getVolumeSet(vvset_name)
                # Ensure flash-cache-policy is set on the vvset
                assert vvset['flashCachePolicy'], 1
                # Ensure the created volume is a member of the vvset
                assert backend_volume_name, [vv_name for vv_name in vvset['setmembers']]

            else:
                vvset_name = utils.get_3par_vvset_name(backend_volume_id)
                vvset = hpe3par_cli.getVolumeSet(vvset_name)
                # Ensure vvset is not available in 3par.
                assert vvset, None
        if 'compression' in kwargs:
            if kwargs['compression'] == 'true':
                assert hpe3par_volume['compressionState'], 1
            else:
                assert hpe3par_volume['compressionState'], 2
        if 'clone' in kwargs:
            if "snapcpg" in kwargs:
                assert hpe3par_volume['snapCPG'], kwargs['snapcpg']
            else:
                if 'backend' in kwargs:
                    assert hpe3par_volume['snapCPG'], kwargs["SNAP_CPG2"]
                else:
                    assert hpe3par_volume['snapCPG'], kwargs["SNAP_CPG"]
            assert hpe3par_volume['copyType'], 1
        if 'qos' in kwargs:
            vvset = hpe3par_cli.getVolumeSet(vvs_name)
            assert vvset['qosEnabled'], True
            qos = hpe3par_cli.queryQoSRule(vvs_name)
            assert qos != None
            assert backend_volume_name, [vv_name for vv_name in vvset['setmembers']]

        if 'importVol' in kwargs:
            assert docker_volume_name, kwargs['importVol']
            assert hpe3par_volume['name'][:3], "dcv"
        if 'cpg' in kwargs:
            assert hpe3par_volume['userCPG'], kwargs['cpg']
        if 'snapcpg' in kwargs:
            assert hpe3par_volume['snapCPG'], kwargs['snapcpg']

        hpe3par_cli.logout()

