from os import path
import yaml
import unittest
import time
from kubernetes import *
config.load_kube_config()
api_instance = client.CoreV1Api()
class KubernetesAutomationTest(unittest.TestCase):

    def hpe_create_pv_object(self,PV_NAME,PV_storage,access,HPE_driver,volume_name):

        print("Test case of PV started")
        flex = client.V1FlexPersistentVolumeSource(driver=HPE_driver,options={"name":volume_name})
        specification = client.V1PersistentVolumeSpec(capacity={"storage":PV_storage},access_modes=[access],
                                                    flex_volume=flex)
        pv_object = client.V1PersistentVolume(api_version="v1", kind="PersistentVolume",
                                     metadata=client.V1ObjectMeta(name=PV_NAME), spec=specification)

        pv_api_response = api_instance.create_persistent_volume(body=pv_object)
        print("Persitent volume created. status='%s'" % str(pv_api_response.status))
#        self.assertIn('name', api_response)
        return pv_object


    def hpe_create_pvc_object(self,PVC_NAME,PVC_storage,access):
        print("PVC function called")
        specification = client.V1PersistentVolumeClaimSpec(access_modes=[access],
                                             resources=client.V1ResourceRequirements(requests={"storage":PVC_storage}))
        pvc_object = client.V1PersistentVolumeClaim(kind="PersistentVolumeClaim", api_version="v1",
                                             metadata=client.V1ObjectMeta(name=PVC_NAME), spec=specification)
        pvc_api_response = api_instance.create_namespaced_persistent_volume_claim(namespace="default", body=pvc_object)
        print("Persitent volume claim created. status='%s'" % str(pvc_api_response.status))

        return pvc_object
    
    def hpe_create_pod_object(self,PVC_NAME,POD_NAME):
        volume_spec = client.V1Volume(name="export",persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=PVC_NAME))
        environment1 = client.V1EnvVar(name="MINIO_ACCESS_KEY",value="minio")
        environment2 = client.V1EnvVar(name="MINIO_SECRET_KEY",value="doryspeakswhale")
        container_spec = client.V1Container(name="minio", image="minio/minio:latest", args=["server","/export"],
                                            env=[environment1,environment2],ports=[client.V1ContainerPort(container_port=9000)],
                                            volume_mounts=[client.V1VolumeMount(name="export", mount_path="/export")])
        specification = client.V1PodSpec(containers=[container_spec], volumes=[volume_spec])
        pod_object = client.V1Pod(api_version="v1", kind="Pod", metadata=client.V1ObjectMeta(name=POD_NAME),
                       spec=specification)
        api_response = api_instance.create_namespaced_pod(namespace="default", body=pod_object)
        print("pod created. status='%s'" % str(api_response.status))
        return pod_object


    def hpe_delete_pod(self,POD_NAME):
        api_response = api_instance.delete_namespaced_pod(name=POD_NAME, namespace="default")
        print("pod deleted. status='%s'" % str(api_response.status))

    def hpe_delete_pvc(self,PVC_NAME):
        api_response = api_instance.delete_namespaced_persistent_volume_claim(name=PVC_NAME, namespace="default")
        print("Persistent volume claim deleted. status='%s'" % str(api_response.status))

    def hpe_delete_pv(self,PV_NAME):
        api_response = api_instance.delete_persistent_volume(name=PV_NAME)
        print("Persistent volume deleted. status='%s'" % str(api_response.status))
