from hpe_3par_kubernetes_manager import KubernetesAutomationTest
import yaml
import pytest
import configparser


pv_name = ""
pvc_name = ""
pod_name = ""
pod_node_name = ""
backend_volume_name = ""
vv_wwn = ""
timeout = 600
HPE3PAR_API_URL = ""
HPE3PAR_IP = ""
HPE3PAR_USERNAME = ""
HPE3PAR_PWD = ""
ISCSI_IP = ""
disk_partitions_by_ip = {}
disk_partition = []
logger = None

import pdb

class TestK8S(KubernetesAutomationTest):

    @pytest.fixture(scope='class')
    def read_config(self):
        global HPE3PAR_API_URL, HPE3PAR_IP, ISCSI_IP, HPE3PAR_USERNAME, HPE3PAR_PWD, logger
        try:
            # read configuration from hpe.conf
            config = configparser.RawConfigParser()
            config.read('/etc/hpedockerplugin/hpe.conf')
            HPE3PAR_API_URL = str(config.get('3par1', 'hpe3par_api_url'))
            HPE3PAR_IP = str(config.get('3par1', 'san_ip'))
            HPE3PAR_USERNAME = str(config.get('3par1', 'hpe3par_username'))
            HPE3PAR_PWD = str(config.get('3par1', 'hpe3par_password'))
            ISCSI_IP = str(config.get('3par1', 'hpe3par_iscsi_ips')).split(",")

            print("\n========== configurations from hpe.conf")
            print("HPE3PAR_API_URL :: %s " % HPE3PAR_API_URL)
            print("HPE3PAR_IP :: %s " % HPE3PAR_IP)
            print("HPE3PAR_USERNAME :: %s " % HPE3PAR_USERNAME)
            print("HPE3PAR_PWD :: %s " % HPE3PAR_PWD)
            print("ISCSI_IP :: %s " % ISCSI_IP)
        except Exception as e:
            print("Exception while reading hpe.conf:: %s" % e)
            raise e

    # @pytest.mark.usefixtures("read_config")
    def test_create_objects(self,read_config):
        print("\n########################### test_create_objects ###########################")
        try:
            # Create PV, PVC and Pod
            pdb.set_trace()
            yml = "YAML/thin30.yml"
            global pv_name, pvc_name, pod_name, pod_node_name
            with open(yml) as f:
                elements = list(yaml.safe_load_all(f))
                for el in elements:
                    #print("======== kind :: %s " % str(el.get('kind')))
                    if str(el.get('kind')) == "PersistentVolume":
                        #print("PersistentVolume YAML :: %s" % el)
                        print("\nCreating PV...")
                        pv_name = self.hpe_create_pv_object(el).metadata.name
                        print("\nPersistentVolume %s created." % pv_name)
                    if str(el.get('kind')) == "PersistentVolumeClaim":
                        assert self.check_status(timeout, pv_name, kind='pv',
                                                 status='Available') == True, "Persistent Volume status check timed out"
                        #import pytest; pytest.set_trace()
                        #print("PersistentVolumeClaim YAML :: %s" % el)
                        print("\nCreating PVC...")
                        pvc_name = self.hpe_create_pvc_object(el).metadata.name
                        print("\nPersistentVolumeClaim %s created." % pvc_name)
                    if str(el.get('kind')) == "Pod":
                        assert self.check_status(timeout, pvc_name, kind='pvc',
                                                 status='Bound') == True, "Persistent Volume Claim status check timed out"
                        #print("Pod YAML :: %s" % el)
                        print("\nCreating Pod...")
                        pod_obj = self.hpe_create_pod_object(el)
                        pod_name = pod_obj.metadata.name
                        assert self.check_status(timeout, pod_name, kind='pod',
                                                 status='Running') == True, "Pod status check timed out"
                        #import pytest;
                        #pytest.set_trace()
                        print("\nPod %s created." % pod_name)
        except Exception as e:
            print("Exception while creating objects :: %s" % e)
            raise e

    def test_verify_on_3par(self, vvs_name=None, **kwargs):
        print("\n########################### test_verify_on_3par ###########################")
        #print("PVC Name in test_verify_on_3par() :: %s " % pvc_name)
        import pdb
        pdb.set_trace()
        pvc_obj = self.get_pvc_obj(pvc_name)
        #print("pvc_obj :: %s " % pvc_obj)
        global backend_volume_name
        volume_name = pvc_obj.spec.volume_name
        print("Docker Volume name :: %s " % volume_name)

        volume_from_docker = self.get_docker_client().inspect_volume(volume_name)
        #print("Volume inspect :: %s " % volume_from_docker)
        #print("type is %s " % type(volume_from_docker))
        # Get volume details from 3Par array
        backend_volume_name = volume_from_docker['Status']['volume_detail']['3par_vol_name']
        backend_volume_id = volume_from_docker['Status']['volume_detail']['id']

        print("3PAR Volume name :: %s " % backend_volume_name)
        #import pytest;
        #pytest.set_trace()

        hpe3par_cli = self._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                      HPE3PAR_USERNAME, HPE3PAR_PWD)
        hpe3par_volume = hpe3par_cli.getVolume(backend_volume_name)
        hpe3par_cli.logout()

        #import pytest;
        #pytest.set_trace()

        #print("Volume from 3PAR :: %s " % hpe3par_volume)
        print("Verifying volume %s on 3PAR..." % backend_volume_name)
        self.verify_volume_on_3par(hpe3par_volume, backend_volume_name, backend_volume_id, volume_name,
                                   HPE3PAR_API_URL=HPE3PAR_API_URL, HPE3PAR_IP=HPE3PAR_IP,
                                   HPE3PAR_USERNAME=HPE3PAR_USERNAME, HPE3PAR_PWD=HPE3PAR_PWD)
        #import pytest;
        #pytest.set_trace()

    def test_verify_cluster_vlun(self):
        import pdb
        pdb.set_trace()
        print("\n########################### test_verify_cluster_vlun ###########################")
        global backend_volume_name, pod_name, pod_node_name, vv_wwn

        #import pytest;
        #pytest.set_trace()
        hpe3par_cli = self._hpe_get_3par_client_login(HPE3PAR_API_URL, HPE3PAR_IP,
                                                      HPE3PAR_USERNAME, HPE3PAR_PWD)
        hpe3par_vlun = hpe3par_cli.getVLUN(backend_volume_name)
        pod_node_name = self.hpe_get_pod(pod_name).spec.node_name
        # print("VLUN on 3PAR :: %s " % hpe3par_vlun)
        # print("WWN on 3PAR :: %s " % vv_wwn)
        lun = hpe3par_vlun['lun']
        vv_wwn = hpe3par_vlun['volumeWWN']
        node_name = hpe3par_vlun['hostname']

        print("VLUN on 3PAR :: %s " % lun)
        print("WWN on 3PAR :: %s " % vv_wwn)
        #print("Pod %s is mounted on %s " % (pod_name, node_name))

        #import pytest;
        #pytest.set_trace()

        # test if node name received from pod and 3par are same
        #assert str(pod_node_name) == str(node_name)

        # verify ls -lrth /dev/disk/by-path at node
        # ls_disk = self.get_command_output(node_name, "ls -lrth /dev/disk/by-path")
        # print("#### ls -lrth output for %s is \n%s " % (node_name,ls_disk))
        print("Verifying output of ls -lrth /dev/disk/by-path...")
        for ip in ISCSI_IP:
            print("== For IP::%s " % ip)
            command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-0))$/ {print $NF}' | awk -F'../' '{print $NF}'"
            # print("command is %s " % command)
            partitions = self.get_command_output(node_name, command)
            print("== Partition(s) received for %s are %s", (ip, partitions))
            assert len(partitions) > int(0), "Partition not found for iscsi-ip %s " % ip
            disk_partitions_by_ip[ip] = partitions

            for partition in partitions:
                disk_partition.append(partition)
            # print("Partition name %s" % partitions)

        print("Partitions :: \n%s" % disk_partitions_by_ip)
        #import pytest;
        #pytest.set_trace()

        print("Fetching DM(s)...")
        # fetch dm from /dev/mapper
        command = "ls -ltrh /dev/mapper/ | awk -v IGNORECASE=1 '$9~/^[0-9]" + vv_wwn.upper() + "/ {print$NF}' | awk -F'../' '{print$NF}'"
        # print("dev/mapper command to get dm :: %s "%command)
        dm = self.get_command_output(node_name, command)
        print("DM(s) received :: %s " % dm)

        #import pytest;
        #pytest.set_trace()

        print("Verifying multipath -ll output...")
        # Verify multipath -ll output
        command = "sudo multipath -ll | awk -v IGNORECASE=1 '/^([0-9]" + vv_wwn + ")\s+(" + dm[0] + ")\s+(3PARdata,VV)/{x=NR+4}(NR<=x){print}'"
        # print("multipath -ll command to :: %s " % command)
        paths = self.get_command_output(node_name, command)
        print("multipath output ::%s \n\n" % paths)
        index = 0
        multipath_failure_flag = 0
        disk_partition_temp = disk_partition
        for path in paths:
            if index < 3:
                index += 1
                continue
            # print(path.split())
            col = path.split()
            print(col)
            print(col[2])

            if col[2] in disk_partition_temp:
                print("col[2] :: %s " % col[2])
                disk_partition_temp.remove(col[2])
                if col[4] != 'active' or col[5] != 'ready' or col[6] == 'running':
                    print("col[4]:col[5]:col[6] :: %s:%s:%s " % (col[4], col[5], col[6]))
                    multipath_failure_flag+=1

        assert multipath_failure_flag != 0, "multipath check failed for %s iscsi ips" % multipath_failure_flag

        #import pytest;
        #pytest.set_trace()
        # print("modified disk_partition = %s" % disk_partition_temp)
        assert len(disk_partition_temp) == 0, "partition mismatch"

        print("Verifying lsscsi output...")
        # Verify lsscsi output
        command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
        partitions = self.get_command_output(node_name, command)

        #print("partitions after lsscsi %s " % partitions)
        assert partitions.sort() == disk_partition.sort(), "lsscsi verificatio failed"
        #import pytest;
        #pytest.set_trace()

    def test_verify_delete_objects(self):
        print("\n########################### test_delete_objects ###########################")
        #import pytest;
        import pdb
        pdb.set_trace()
        #pytest.set_trace()
        try:
            # Delete PV, PVC and Pod
            global pv_name, pvc_name, pod_name, pod_node_name
            # delete pod first
            print("Deleting Pod...")
            #import pytest;
            #pytest.set_trace()
            pod_delete_resp = self.hpe_delete_pod_object(pod_name)
            # print("Pod deletion response.  ::  %s " % pod_delete_resp)
            if self.check_if_deleted(timeout, pod_name, "pod"):
                assert pod_name not in self.hpe_list_pod_objects_names(), "pod %s is not deleted yet " % pod_name

            print("\npod is deleted now, lets delete pvc...")
            print("Deleting PVC...")
            #import pytest;
            #pytest.set_trace()
            pvc_delete_resp = self.hpe_delete_pvc_object_by_name(pvc_name)
            # print("PVC deletion response.  ::  %s " % pvc_delete_resp)
            if self.check_if_deleted(timeout, pvc_name, "pvc"):
                assert pvc_name not in self.hpe_list_pvc_objects_names(), "pvc %s is not deleted yet " % pvc_name

            print("\npvc is deleted now, lets delete pv...")
            print("Deleting PV...")
            #import pytest;
            #pytest.set_trace()
            pv_delete_resp = self.hpe_delete_pv_object_by_name(pv_name)
            #print("PV deletion response.  ::  %s " % pv_delete_resp)
            if self.check_if_deleted(timeout, pv_name, "pv"):
                assert pv_name not in self.hpe_list_pv_objects_names(), "pv %s is not deleted yet " % pv_name

            print("\npv is deleted now, lets delete volume...")
            print("Deleting docker volume...")
            #import pytest;
            #pytest.set_trace()
            self.get_docker_client().remove_volume(pv_name, force=False)
            #print("Volumes list after volume deletion :: " % self.get_docker_client().volumes())
            print("Volume is deleted.")

        except Exception as e:
            print("Exception :: %s" % e)
            raise e

    def test_verify_deleted_lun(self):
        print("\n########################### test_delete_objects ###########################")
        import pdb
        pdb.set_trace()
        try:
            print("Verifying 'ls -lrth /dev/disk/by-path' entries are cleaned...")
            # verify ls -lrth /dev/disk/by-path at node
            for ip in ISCSI_IP:
                print("For IP::%s " % ip)
                command = "ls -lrth /dev/disk/by-path | awk '$9~/^((ip-" + ip + ").*(lun-0))$/ {print $NF}' | awk -F'../' '{print $NF}'"
                # print("command is %s " % command)
                partitions = self.get_command_output(pod_node_name, command)
                assert len(partitions) == int(0), "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip
                disk_partitions_by_ip[ip] = partitions

                for partition in partitions:
                    disk_partition.append(partition)
                print("Partition name %s" % partitions)

            #import pytest;
            #pytest.set_trace()

            print("Verifying 'multipath -ll' entries are cleaned...")
            #import pytest;
            #pytest.set_trace()
            # Verify multipath -ll output
            command = "multipath -ll | awk -v IGNORECASE=1 '/^([0-9]" + vv_wwn + ").*(3PARdata,VV)/{x=NR+4}(NR<=x){print}'"
            # print("multipath -ll command to :: %s " % command)
            paths = self.get_command_output(pod_node_name, command)
            assert len(paths) == 0, "Multipath entries are not cleaned"

            #import pytest;
            #pytest.set_trace()

            print("Verifying 'lsscsi' entries are cleaned...")
            #import pytest;
            #pytest.set_trace()
            # Verify lsscsi output
            command = "lsscsi | awk '$3~/3PARdata/ && $4~/VV/' | awk -F'/dev/' '{print $NF}'"
            partitions = self.get_command_output(pod_node_name, command)
            print("partitions after lsscsi %s " % partitions)
            assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"

        except Exception as e:
            print("Exception :: %s" % e)
            raise e





