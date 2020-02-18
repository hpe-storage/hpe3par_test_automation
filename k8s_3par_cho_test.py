import argparse
import logging
from multiprocessing import Pool
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
#from hpe3parclient import exceptions as exc
#from hpe3parclient.client import HPE3ParClient
config.load_kube_config()
client.configuration.assert_hostname = False
api_instance = client.CoreV1Api()


logger = None

totalActions = 0
totalActions_create_pod = 0
totalActions_delete_pod = 0

# Setting a 10 min timeout
timeout =600


totalErrors = 0
totalErrors_create_pod = 0
totalErrors_delete_pod = 0

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


prompt_for_arg(args, "maxPods", "Max number of pod to be created (8): ", "8")
prompt_for_arg(args, "duration", "Test duration in minutes: ", "1")
#prompt_for_arg(args, "plugin", "Name of the plugin repository with version ", "hpe:latest")

args.duration = int(args.duration)
maxPods = int(args.maxPods)
HPE3PAR = args.plugin


def SetupLogging(logfile=None):
    
    #create logger
    global logger
    logger = logging.getLogger()
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
    global totalActions
    global totalActions_create_pod
    global totalActions_delete_pod        

    totalActions += actionIncrement
    
    entry = "[A:%d,E:%d] %s" % (totalActions, totalErrors, msg)
    logger.info(entry)


    if action and action == "create_pod":
        totalActions_create_pod += actionIncrement
    elif action and action == "delete_pod":
        totalActions_delete_pod += actionIncrement


    if msg == "break out wait after 15 minutes...":
        dump = commands.getstatusoutput('top -bn1')
        entry = "[A:%d,E:%d] %s" % (totalActions, totalErrors, dump)
        logger.info(entry)


def LogError(msg="", errorIncrement=1, action=None):

    global totalErrors
    global totalErrors_create_pod
    global totalErrors_delete_pod


    totalErrors += errorIncrement

    entry = "[A:%d,E:%d] ERROR >>>>>> %s" % (totalActions, totalErrors, msg)
    logger.info(entry)

    if action and action == "create_pod":
        totalErrors_create_pod += errorIncrement
    elif action and action == "delete_pod":
        totalErrors_delete_pod += errorIncrement



def TestFinished():
    global clock_start
    LogMessage( "Test performed %s actions." % totalActions)
    LogMessage( "Test performed %s create pod actions." % totalActions_create_pod)
    LogMessage( "Test performed %s delete pod actions." % totalActions_delete_pod)


    LogMessage( "Test observed  %s errors." % totalErrors)
    LogMessage( "Test observed  %s create pod errors." % totalErrors_create_pod)
    LogMessage( "Test observed  %s delete pod errors." % totalErrors_delete_pod)


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

def test_create_pv_pvc(yml):

    try: 
        LogMessage( "---------------Creating pv and pvc's----------------") 
        with open(yml, 'r+') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) == "PersistentVolume":
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
                        pv_name = api_instance.create_persistent_volume(el).metadata.name

                elif str(el.get('kind')) == "PersistentVolumeClaim":
                    assert check_status(timeout, pv_name, kind='pv',
                                                status='Available') == True, "Persistent Volume Claim status check timed out"
                    el['metadata']['name'] = pvc_random_name()
                    pvc_name = api_instance.create_namespaced_persistent_volume_claim(namespace="default",body=el).metadata.name
                    assert check_status(timeout, pvc_name, kind='pvc',
                                                status='Bound') == True, "Persistent Volume Claim status check timed out"


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


def test_create_pod():
    existing_pvc  = api_instance.list_persistent_volume_claim_for_all_namespaces().items
    existing_pvc_list =[]
    # Creating a list of existing pvcs

    for pvc in existing_pvc:
        existing_pvc_list.append(pvc.metadata.name)

    #Creating pods
    with Pool(processes=maxPods) as p:
        p.map(create_pod,existing_pvc_list)

    '''#Creating pods
    create_pod(existing_pvc_list[0])'''



def create_pod(pvc_name):
    yml ="/root/openshift_bootstrap/Kubernetes_automation/YAMLs_for_3.3_plugin-testing/driverless.yml"
    try: 
        with open(yml, 'r+') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) =="Pod":
                    assert check_status(timeout, pvc_name, kind='pvc',
                                 status='Bound') == True, "Persistent Volume Claim status check timed out"
                    el['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = pvc_name

                    el['metadata']['name'] = pod_random_name()
                    pod_obj  = api_instance.create_namespaced_pod(namespace="default", body=el)
                    pod_name  = pod_obj.metadata.name
                    assert check_status(timeout, pod_name, kind='pod',
                                  status='Running') == True, "Create pod status check timed out"
                    time.sleep(30)
                    pod_running_obj = api_instance.read_namespaced_pod(pod_name, 'default')

                    pod_node_name = pod_running_obj.spec.node_name
                    LogMessage("-------------------Starting creation of pod action----------------------------" )
                    pvc_obj = api_instance.read_namespaced_persistent_volume_claim(pvc_name, namespace="default")
                    pv_name = pvc_obj.spec.volume_name 

                    LogMessage("************Successfully completed %s operation.**************" % 'create_pod',1,'create_pod')

    except AssertionError as error:
        LogError(str(error), 1, "create_pod")

    except Exception as error:
        LogError(str(error), 1, "create_pod")

 
    #Validate block
    try:

        #Docker volume inspect in volume to 3par volume name 
        docker_client = docker.from_env(version=TEST_API_VERSION)
        LogMessage("-------------------Validating volume details on 3par----------------------------" )

        hpe_3par_vol = docker_client.volumes.get(pv_name) 
        Vol_wwn = hpe_3par_vol.attrs['Mountpoint'].split('/')[4].split('-')[4]
        Vol_name = hpe_3par_vol.attrs['Status']['volume_detail']['3par_vol_name']

        # Checking wwn in /dev/disk/by-id folder
        LogMessage("--------------------------Validating 3par wwn details in /dev/disk/by-id folder----------")
        by_id = get_by_id_output(pod_node_name, Vol_wwn)
        by_id_vol_wwn = by_id.split()[8].split('-')[3]
        by_id_vol_dm = by_id.split()[10].split('/')[2]

        # Checking wwn details in mutipath -ll command
        LogMessage("--------------------------Validating 3par wwn details in multipath -ll output--------------" )
        multi_path_info = get_multipath_output(pod_node_name, Vol_wwn)
        multipath_vol_wwn = multi_path_info[0].split()[0]
        multipath_vol_dm = multi_path_info[0].split()[1]
        multi_path_info.pop(0)
        disks = []
        for x in multi_path_info:
            disks.append(x.split()[2])
        assert multipath_vol_wwn == by_id_vol_wwn, "'wwn' of multipath output does not match value in by-id folder"
        assert multipath_vol_dm == by_id_vol_dm, "'dm' of multipath output does not match value in by-id folder"

        #Checking wwn details in /dev/disk/by-path folder
        LogMessage("---------------------------Validating 3par wwn details in /dev/disk/by-path folder--------" )
        by_path = get_by_path_output(pod_node_name, disks)
        assert len(disks) == len(by_path), "volume path value mismatch"

    except Exception as error:
        LogError(str(error))
         
    except AssertionError as error:
        LogError(str(error))

    # Introducing manual sleep for 5 mins to ensure IO runs on mounted volume
    time.sleep(3)


    #Deleting pod 

    try:
        #Deleting pod while IO on volume is in progress
        LogMessage("----------------Starting deletion of pod--------------------------------")
        pod_delete_api_response = api_instance.delete_namespaced_pod(name=pod_name, namespace="default")
        assert check_delete_status(timeout, pod_name, kind='pod',
                                                 status='Terminating') == True, "Delete pod status check timed out"
        LogMessage("************Successfully completed %s operation.**************" % 'delete_pod',1,'delete_pod')

    except AssertionError as error:
        LogError(str(error), 1, "delete_pod")

    except Exception as error:
        LogError(str(error), 1, "delete_pod")    


def get_by_id_output(node_name, Vol_wwn):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=node_name)
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
        ssh_client.connect(hostname=node_name)
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
        ssh_client.connect(hostname=node_name)
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
        time.sleep(10)

    return flag



def check_delete_status(timeout, name, kind, status):
    count = 0
    flag = True
    try:
        while True:
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
            if (obj.status.phase == 'Terminating' or obj.status.phase == 'Running'):
                continue
            elif int(count) > int(timeout):
                flag = False
                break
            else:
                break
            count += 1
            time.sleep(10)
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

LogMessage("=====================STARTING %s TESTS===================" % os.path.basename(os.sys.argv[0]))
import pdb
pdb.set_trace()
LogMessage("Args: %s" % args)


try:

    ######################################################
    # Defining actions and % of time they should be performed (from previous entry to %)
    # create pod    - 15%
    # delete pod  - 12%
    #######################################################


    hour_start = time.time()
    count = 0
    


    while (count < maxPods+3):
        yml = "/root/openshift_bootstrap/Kubernetes_automation/YAMLs_for_3.3_plugin-testing/driverless.yml"
        test_create_pv_pvc(yml)
        count= count +1

    while (time.time() - clock_start) < int(args.duration) * 60:

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




############################################
LogMessage("==================================================================")
TestFinished()
LogMessage("FINISHED")



