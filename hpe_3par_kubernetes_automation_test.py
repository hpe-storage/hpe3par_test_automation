from os import path
import os
import yaml
from time import sleep
import pytest
from kubernetes import *
from hpe_3par_kubernetes_manager import KubernetesAutomationTest
config.load_kube_config()
api_instance = client.CoreV1Api()

class SampleTest(KubernetesAutomationTest):

    def test_create_sample_pv_pvc_pod(self):
    
        PV_NAME="pv-test"
        PVC_NAME="pvc-test"
        POD_NAME="pod-test"
    	access="ReadWriteOnce"
    	HPE_driver="hpe.com/hpe"
        volume_name="TEST-VOLUME"
        PVC_storage="10Gi"
    	PV_storage="35Gi"
    
        PV=self.hpe_create_pv_object(PV_NAME,PV_storage,access,HPE_driver,volume_name)
        PVC=self.hpe_create_pvc_object(PVC_NAME,PVC_storage,access)
        sleep(3)
        POD=self.hpe_create_pod_object(PVC_NAME,POD_NAME)
    	print (POD)


    def test_delete_sample_pv_pvc_pod(self):

        print("Delete operations started")
        PV_NAME="pv-test"
        PVC_NAME="pvc-test"
        POD_NAME="pod-test"
        volume_name="TEST-VOLUME"
        self.hpe_delete_pod(POD_NAME)
        sleep(10)
        self.hpe_delete_pvc(PVC_NAME)
        self.hpe_delete_pv(PV_NAME)
