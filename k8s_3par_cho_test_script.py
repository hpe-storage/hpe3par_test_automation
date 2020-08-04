import argparse
import logging
import multiprocessing
from multiprocessing import Pool, Value
from datetime import timedelta
import os
import paramiko
import docker
from os import path
import yaml
import unittest
import time
import random
from kubernetes import *
from hpe3parclient.client import HPE3ParClient
config.load_kube_config()
client.configuration.assert_hostname = False
api_instance = client.CoreV1Api()
k8s_storage_v1 = client.StorageV1Api()


logger = None

secret_name =""
tA = None
tA_cp = None
tA_dp = None
sc_name = ""
existing_pvc_list =[]

# Setting a 10 min timeout
timeout =600

tE = None
tE_cp = None
tE_dp = None

parser = argparse.ArgumentParser()
parser.add_argument("-maxPods")
parser.add_argument("-duration")
parser.add_argument("-plugin")
parser.add_argument("-logfile", default=("./K8sCHOTest-%d.log" % time.time()))
args = parser.parse_args()
clock_start = time.time()

#Reading from cho_config file

with open("cho_test_config.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)


#Declaring global variables
HPE3Par_IP = cfg['backend']['3Par_IP']
HPE3Par_PWD = cfg['backend']['3Par_PWD']
HPE3Par_userId = cfg['backend']['3Par_userId']
HPE3Par_api_url= cfg['backend']['3Par_api_url']
duration = cfg['runConfig']['duration']
maxPods = cfg['runConfig']['maxPods']
TEST_API_VERSION = os.environ.get('DOCKER_TEST_API_VERSION')

def prompt_for_arg(arg, field, prompt, default):
    if getattr(arg, field) is None:
        try:
            r =input(prompt)
            if len(r) > 0:
                setattr(arg, field, r)
            else:
                setattr(arg, field, default)
        except:
            print("Aborted.")
            sys.exit()

#prompt_for_arg(args, "maxPods", "Max number of pod to be created (8): ", "8")
#prompt_for_arg(args, "duration", "Test duration in minutes: ", "1")
#prompt_for_arg(args, "plugin", "Name of the plugin repository with version ", "hpe:latest")

'''args.duration = int(args.duration)
maxPods = int(args.maxPods)
HPE3PAR = args.plugin'''


def SetupLogging(logfile=None):

    #create logger
    global logger
    #logger = logging.getLogger()
    logger = multiprocessing.log_to_stderr()
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s%(message)s', datefmt="[%Y-%m-%d][%H:%M:%S]")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # add log to file on disk
    if logfile:
        ch = logging.FileHandler(logfile,"w")
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


def LogMessage(msg="", actionIncrement=0,action=None):

    global tA
    global tA_cp
    global tA_dp

    with tA.get_lock():
        tA.value += actionIncrement

    entry = "[A:%d,E:%d] %s" % (tA.value, tE.value, msg)
    logger.info(entry)


    if action and action  == "create_pod":
        with tA_cp.get_lock():
            tA_cp.value += actionIncrement
    elif action and action  == "delete_pod":
        with tA_dp.get_lock():
            tA_dp.value += actionIncrement


    if msg == "break out wait after 15 minutes...":
        dump = commands.getstatusoutput('top -bn1')
        entry = "[A:%d,E:%d] %s" % (tA.value, tE.value, dump)
        logger.info(entry)


def LogError(msg="", errorIncrement=1, action=None):

    global tE
    global tE_cp
    global tE_dp


    with tE.get_lock():
        tE.value += errorIncrement

    entry = "[A:%d,E:%d] ERROR >>>>>> %s" % (tA.value, tE.value, msg)
    logger.info(entry)

    if action  == "create_pod":
        with tE_cp.get_lock():
            tE_cp.value += errorIncrement
    elif action  == "delete_pod":
        with tE_dp.get_lock():
            tE_dp.value += errorIncrement

def cleanup():
    try:
        #Cleaning up pvc's and storage class before reporting run summary
        for pvc in existing_pvc_list:
            del_pvc_resp =api_instance.delete_namespaced_persistent_volume_claim(pvc, namespace="default")


        del_sc_resp =api_instance.delete_namespaced_secret(secret_name, namespace="kube-system")
        del_sc_resp =k8s_storage_v1.delete_storage_class(sc_name)

    except client.rest.ApiException as e:
        LogError(str(e))

    except Exception as e:
        LogError(str(e))

     




def TestFinished():
    global clock_start
    
    LogMessage( "Test performed %s actions." % tA.value)
    LogMessage( "Test performed %s create pod actions." % tA_cp.value)
    LogMessage( "Test performed %s delete pod actions." % tA_dp.value)


    LogMessage( "Test observed  %s errors." % tE.value)
    LogMessage( "Test observed  %s create pod errors." % tE_cp.value)
    LogMessage( "Test observed  %s delete pod errors." % tE_dp.value)


    LogMessage( "Total test time: %s" % timedelta(seconds=time.time()-clock_start))
    LogMessage( "Test finished.")



class TestError:
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

def get_docker_client(self):
    docker_client =docker.APIClient(
        version=TEST_API_VERSION, timeout=60, **kwargs_from_env()
    )


def test_create_secret_sc(yml):
    try:
        LogMessage( "---------------Creating sc----------------")
        global sc_name
        global secret_name
        with open(yml, 'r+') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) == "StorageClass":
                    resp = k8s_storage_v1.create_storage_class(body=el)
                    sc_name = resp.metadata.name
                    print("Storage Class created. status=%s" % resp.metadata.name)
                    #return resp
                if str(el.get('kind')) == "Secret":
                    resp = obj = api_instance.create_namespaced_secret(namespace="kube-system", body=el)
                    secret_name = resp.metadata.name
                    print("Secret created. status=%s" % resp.metadata.name)
                    #return resp

    except client.rest.ApiException as e:
        print("Exception :: %s" % e)
        raise e

def test_create_pv_pvc(yml):

    try:
        LogMessage( "---------------Creating pv and pvc's----------------")
        with open(yml, 'r+') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                '''if str(el.get('kind')) == "PersistentVolume":
                    el['metadata']['name'] = pv_random_name()

                    #Checking if persistent volume list is not null
                    if not api_instance.list_persistent_volume().items:
                        pv_name = api_instance.create_persistent_volume(el).metadata.name


                    #Checking if pv name exists in list
                    existing_pv = api_instance.list_persistent_volume().items
                    existing_pv_list = []
                    for pv in existing_pv:
                        existing_pv_list.append(pv.metadata.name)

                    if el['metadata']['name'] in existing_pv_list:
                        break
                    else:
                        pv_name = api_instance.create_persistent_volume(el).metadata.name'''

                if str(el.get('kind')) == "PersistentVolumeClaim":
                    '''assert check_status(timeout, pv_name, kind='pv',
                                                status='Available') == True, "Persistent Volume Claim status check timed out"'''
                    el['metadata']['name'] = pvc_random_name()
                    pvc_name = api_instance.create_namespaced_persistent_volume_claim(namespace="default",body=el).metadata.name
                    assert check_status(timeout, pvc_name, kind='pvc',
                                                status='Bound') == True, "Persistent Volume Claim status check timed out"


    except client.rest.ApiException as e:
        LogError(str(e))

    except AssertionError as e:
        LogError(str(e))

    except Exception as e:
        LogError(str(e))


def hpe_get_3par_client_login(HPE3Par_api_url, HPE3Par_IP, HPE3Par_userId, HPE3Par_PWD):
    # Login to 3Par array and initialize connection for WSAPI calls
    hpe_3par_cli = HPE3ParClient(HPE3Par_api_url, True, False, None, True)
    hpe_3par_cli.login(HPE3Par_userId, HPE3Par_PWD)
    hpe_3par_cli.setSSHOptions(HPE3Par_IP, HPE3Par_userId, HPE3Par_PWD)
    return hpe_3par_cli


def init(l,m,n,o,p,q):
    global tA
    global tA_cp
    global tA_dp
    tA = l
    tA_cp = m
    tA_dp = n
    global tE
    global tE_cp
    global tE_dp
    tE = o
    tE_cp = p
    tE_dp = q



def test_create_pod():
    existing_pvc  = api_instance.list_persistent_volume_claim_for_all_namespaces().items
    global existing_pvc_list
    # Creating a list of existing pvcs

    for pvc in existing_pvc:
        existing_pvc_list.append(pvc.metadata.name)

    #Creating pods
    with Pool(initializer=init, initargs=(tA,tA_cp,tA_dp,tE,tE_cp,tE_dp,),processes=maxPods) as p:
        #p.map(create_pod,existing_pvc_list)
        p.map(create_pod,existing_pvc_list)

    '''#Creating pods
 
    create_pod(existing_pvc_list[0])'''

def create_pod(pvc_name):
    yml ="test-pvc.yml"
    try:
        action = "create_pod"
        with open(yml, 'r+') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) =="Pod":
                    assert check_status(timeout, pvc_name, kind='pvc',
                                 status='Bound') == True, "Persistent Volume Claim status check timed out"
                    el['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = pvc_name

                    el['metadata']['name'] = pod_random_name()
                    LogMessage("-------------------Starting creation of pod action----------------------------",1 )
                    pod_obj  = api_instance.create_namespaced_pod(namespace="default", body=el)
                    pod_name  = pod_obj.metadata.name
                    assert check_status(timeout, pod_name, kind='pod',
                                  status='Running') == True, "Create pod status check timed out for pod {0}".format(pod_name)
                    time.sleep(30)
                    pod_running_obj = api_instance.read_namespaced_pod(pod_name, 'default')

                    pod_node_name = pod_running_obj.spec.node_name
                    pvc_obj = api_instance.read_namespaced_persistent_volume_claim(pvc_name, namespace="default")
                    pv_name = pvc_obj.spec.volume_name

                    LogMessage("************Successfully completed %s operation for pod {0}.************".format(pod_name) % action,1,action)

    except client.rest.ApiException as e:
        LogError(str(e), 1, "create_pod")

    except AssertionError as error:
        LogError(str(error), 1, "create_pod")

    except Exception as error:
        LogError(str(error), 1, "create_pod")

    #Validate block
    try:

        #Docker volume inspect in volume to 3par volume name
        #docker_client = docker.from_env(version=TEST_API_VERSION)
        hpe_3par_cli =  hpe_get_3par_client_login(HPE3Par_api_url, HPE3Par_IP, HPE3Par_userId, HPE3Par_PWD)
        pv_name = pv_name[:31]

        LogMessage("---------------Validating 3par wwn details in /dev/disk/by-id folder for pvc {0} mounted on pod {1}----------".format(pv_name, pod_name))
        hpe_3par_vol = hpe_3par_cli.getVolume(pv_name)
        hpe_3par_cli.logout()
        #Vol_wwn = hpe_3par_vol.attrs['Mountpoint'].split('/')[4].split('-')[4]
        Vol_wwn = "3{0}".format(hpe_3par_vol["wwn"]).lower()
        #Vol_name = hpe_3par_vol.attrs['Status']['volume_detail']['3par_vol_name']

        # Checking wwn in /dev/disk/by-id folder
        LogMessage("---------------Validating 3par wwn details in /dev/disk/by-id folder for pvc {0} mounted on pod {1}----------".format(pv_name, pod_name))
        by_id = get_by_id_output(pod_node_name, Vol_wwn)
        by_id_vol_wwn = by_id.split()[8].split('-')[3]
        print (by_id_vol_wwn)
        LogMessage(str(by_id_vol_wwn))
        by_id_vol_dm = by_id.split()[10].split('/')[2]
        LogMessage(str(by_id_vol_dm))

        # Checking wwn details in mutipath -ll command
        LogMessage("------------Validating 3par wwn details in multipath -ll output for pvc {0} mounted on pod {1}--------------".format(pv_name, pod_name))
        multi_path_info = get_multipath_output(pod_node_name, Vol_wwn)
        multipath_vol_wwn = multi_path_info[0].split()[0]
        if multipath_vol_wwn.startswith('3'):
            multipath_vol_wwn = multi_path_info[0].split()[0]
            multipath_vol_dm = multi_path_info[0].split()[1]
            #print (multipath_vol_wwn)
            LogMessage(str(multipath_vol_wwn))
            LogMessage(str(multipath_vol_dm))
        else:
            multipath_vol_wwn = multi_path_info[0].split()[1].strip("(").strip(")")
            multipath_vol_dm = multi_path_info[0].split()[2]
            #print (multipath_vol_wwn)
            LogMessage(str(multipath_vol_wwn))
            LogMessage(str(multipath_vol_dm))
        #multipath_vol_dm = multi_path_info[0].split()[1]
        multi_path_info.pop(0)
        disks = []
        for x in multi_path_info:
            disks.append(x.split()[2])
        assert multipath_vol_wwn == by_id_vol_wwn, "'wwn' of multipath output does not match value in by-id folder"
        assert multipath_vol_dm == by_id_vol_dm, "'dm' of multipath output does not match value in by-id folder"
        LogMessage(str(disks))

        #Checking wwn details in /dev/disk/by-path folder
        LogMessage("---------------Validating 3par wwn details in /dev/disk/by-path folder for pvc {0} mounted on pod {1}--------".format(pv_name, pod_name))
        by_path = get_by_path_output(pod_node_name, disks)
        print(disks)
        print(by_path)
        LogMessage(str(by_path))
        #assert len(disks) == len(by_path), "volume path value mismatch"

    except Exception as error:
        LogError(str(error))

    except AssertionError as error:
        LogError(str(error))


    # Introducing manual sleep for 5 mins to ensure IO runs on mounted volume
    time.sleep(3)


    #Deleting pod

    try:
        #Deleting pod while IO on volume is in progress
        LogMessage("----------------Starting deletion of pod {0}--------------------------------".format(pod_name))
        pod_delete_api_response = api_instance.delete_namespaced_pod(name=pod_name, namespace="default")
        assert check_delete_status(timeout, pod_name, kind='pod',
                                                 status='Terminating') == True, "Delete pod status check timed out"
        LogMessage("************Successfully completed %s operation for pod {0}.**************".format(pod_name) % 'delete_pod',1,'delete_pod')
        time.sleep(30)

        # Checking wwn details in mutipath -ll command after pod delete
        LogMessage("------------Validating 3par wwn details in multipath -ll output after pod {0} deletion--------------".format(pod_name))
        multi_path_info = get_multipath_output(pod_node_name, Vol_wwn)
        LogMessage(str(multi_path_info))
        #print(multi_path_info)


    except client.rest.ApiException as e:
        LogError(str(e), 1, "create_pod")

    except AssertionError as error:
        LogError(str(error), 1, "delete_pod")

    except Exception as error:
        LogError(str(error), 1, "delete_pod")

def get_by_id_output(node_name, Vol_wwn):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=node_name,username="root", password="12iso*help")
        stdin,stdout,stderr=ssh_client.exec_command("ls -l /dev/disk/by-id")
        command_output = []
        while True:
            line = stdout.readline()
            if not line:
                break
            elif Vol_wwn in line:
                if "dm-uuid-mpath" in line:
                    command_output = (str(line))
                    break
                else:
                    continue
        ssh_client.close()

        return command_output
    except Exception as e:
        LogError("Exception while logging in to host")

def get_multipath_output(node_name, Vol_wwn):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=node_name, username="root", password="12iso*help")
        stdin,stdout,stderr=ssh_client.exec_command("multipath -ll")
        command_output = []
        #line = stdout.readline()
        while True:
            line = stdout.readline()
            if not line:
                break
            elif Vol_wwn in line:
                command_output.append(str(line))
                while True:
                    line = stdout.readline()
                    if not line:
                        break
                    elif str(line).startswith('3'):
                        break
                    elif str(line).startswith('size'):
                        continue
                    elif 'policy' in str(line):
                        continue
                    else:
                        command_output.append(str(line))
                        #line = stdout.readline()

            #else:
                #line = stdout.readline()
        ssh_client.close()
        return command_output
    except Exception as e:
        LogError("Exception while logging in to host")

def get_by_path_output(node_name, disks):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=node_name,username="root", password="12iso*help")
        stdin,stdout,stderr=ssh_client.exec_command("ls -l /dev/disk/by-path")
        command_output = []
        line = stdout.readline()
        while True:
            if not line:
                #LogError("/dev/disk/by-path output is blank")
                break
            else:
                for a in disks:
                    if (line.find(a) != -1):
                        command_output.append(str(line))
                line = stdout.readline()
        ssh_client.close()

        return command_output
    except Exception as e:
        LogError("Exception while logging in to host")

def check_status(timeout, name, kind, status):
    count = 0
    flag = True

    try:

        while True:
            obj = ""
            if kind == 'pv':
                obj = api_instance.read_persistent_volume(name)
            elif kind == 'pvc':
                obj = api_instance.read_namespaced_persistent_volume_claim(name, namespace="default")
            elif kind == 'pod':
                obj = api_instance.read_namespaced_pod(name, namespace="default")
            else:
                LogError("Unsupported kind in yml")
                flag = False
                break
            if obj.status.phase == status:
                break
            if int(count) > int(timeout):
                flag = False
                break
            count += 1
            time.sleep(1)

    except client.rest.ApiException as e:
        LogError(str(e), 1, "create_pod")
    return flag

def check_delete_status(timeout, name, kind, status):
    count = 0
    flag = True
    pod_names = []
    try:
        while True:
            pod_names = []
            if kind == 'pv':
                obj = api_instance.read_persistent_volume(name)
            elif kind == 'pvc':
                obj = api_instance.read_namespaced_persistent_volume_claim(name, namespace="default")
            elif kind == 'pod':
                obj = api_instance.list_namespaced_pod(namespace="default")
                if not obj.items:
                    pod_names = []
                else:
                    for pod in obj.items:
                        pod_names.append(pod.metadata.name)

            else:
                LogError("Unsupported kind in yml")
                flag = False
                break
            if not pod_names:
                break
            if name not in pod_names:
                break
            if int(count) > int(timeout):
                flag = False
                break
            count += 1
            time.sleep(1)

    except client.rest.ApiException as e:
        LogError(str(e), 1, "delete_pod")

    except Exception as e:
        LogMessage(str(e))
        flag = True

    except HTTPError as e:
        LogMessage(str(e))
        flag = True
    return flag

def pv_random_name():
    return u'pv-{0:x}'.format(random.getrandbits(32))

def pvc_random_name():
    return u'pvc-{0:x}'.format(random.getrandbits(32))

def pod_random_name():
    return u'pod-{0:x}'.format(random.getrandbits(32))

SetupLogging(args.logfile)
random.seed()

#LogMessage("=====================STARTING %s TESTS===================" % os.path.basename(os.sys.argv[0]))
#LogMessage("Args: %s" % args)


try:

    ######################################################
    # Defining actions and % of time they should be performed (from previous entry to %)
    # create pod    - 15%
    # delete pod  - 12%
    #######################################################


    hour_start = time.time()
    count = 0
    tA = Value('i', 0)
    tA_cp = Value('i', 0)
    tA_dp = Value('i', 0)
    tE = Value('i', 0)
    tE_cp = Value('i', 0)
    tE_dp = Value('i', 0)

    yml = "test-pvc.yml"
    test_create_secret_sc(yml)

    while (count < maxPods+15):
        yml = "test-pvc.yml"
        test_create_pv_pvc(yml)
        count= count +1


    while (time.time() - clock_start) < int(duration) * 60:

        processes = []
        try:


            test_create_pod()
            time.sleep(3)
            #pool = Pool(processes=maxPods)
            #pool.map(test_create_pod)
            #LogMessage("************Successfully completed %s operation.**************" % 'create_pod',1,'create_pod')


        except TestError as e:
            LogError(str(e), 1, "create_pod")
            continue




except TestError as e:
    LogError(str(e))
    LogError("Aborting test.  Too frightened to continue.", 0)




LogMessage("==================================================================")
cleanup()
TestFinished()
LogMessage("FINISHED")
