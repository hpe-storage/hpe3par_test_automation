# Vagrant Utility for automated k8s cluster setup

Vagrantfile and ansible playbooks to create single-master k8s cluster with CentOS as base image.
IPs, k8s version and proxy settings are configurable and to be modified in config/config.yml

 
## Prerequisites:
- Vagrant should be installed on your machine. Installation binaries can be found [here](https://www.vagrantup.com/downloads.html)
- Oracle VirtualBox can be used as a Vagrant provider or make use of similar providers as described in [Vagrant’s official documentation](https://www.vagrantup.com/docs/providers/)
- Ansible should be installed in your machine. Refer to the [Ansible installation guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for platform specific installation.
- CentOS box 
- Clone the python-hpedockerplugin repository
  - $ cd ~
  - $ git clone -b k8s_cluster_vagrant https://github.com/saranke/hpe3par_test_automation.git
  - $ cd hpe3par_test_automation
  - Modify config/config.yml and provide master and worker nodes IPs, k8s version and http/https/no-proxy settings.

## Steps to create cluster:
- After setting up prerequisites, execute below command to create single-master k8s cluster.
  - $ cd hpe3par_test_automation
  - $ mode='cluster' vagrant up [ mode='cluster' vagrant up --debug to enable debug logs]

## Automated test execution:

  ### Prerequisite:
  - Docker volume plugin must be installed on all nodes. (Please follow [steps](https://github.com/hpe-storage/python-hpedockerplugin/tree/master/ansible_3par_docker_plugin))
  - Execute install_libs.yml to setup ssh connectivity between k8s cluster nodes for execution of automation test.
  - $ ansible-playbook -i python-hpedockerplugin/ansible_3par_docker_plugin/hosts ./install_libs.yml
    > NOTE: python-hpedockerplugin/ansible_3par_docker_plugin/hosts is needed as node-ips are fetched from the same.

  ### Steps for Automation Test Execution:
    - ssh to master node disabling StrickHostKeyChecking
      - $ ssh -o StrictHostKeyChecking=no master_node_ip
    - Clone test automation 
      - $ git clone -b k8s_auto https://github.com/saranke/hpe3par_test_automation.git
    - $ cd hpe3par_test_automation
    - $ pytest -s
