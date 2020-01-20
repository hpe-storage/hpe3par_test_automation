# Vagrant Utility for automated k8s cluster setup

Vagrantfile and ansible playbooks to create single-master k8s cluster with CentOS as base image.
IPs, k8s version and proxy settings are configurable and to be modified in config/config.yml

 
## Prerequisites:
- CentOS box
- Vagrant should be installed on your machine. Installation binaries can be found [here](https://www.vagrantup.com/downloads.html)
- Oracle VirtualBox can be used as a Vagrant provider or make use of similar providers as described in [Vagrant’s official documentation](https://www.vagrantup.com/docs/providers/)
- Ansible should be installed in your machine. Refer to the [Ansible installation guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for platform specific installation. 
- Some helpful links:
  - [VirtualBox 6.0 installation](https://www.itzgeek.com/how-tos/linux/centos-how-tos/install-virtualbox-4-3-on-centos-7-rhel-7.html)
  - [Vagrant installation](https://phoenixnap.com/kb/how-to-install-vagrant-on-centos-7)
- Clone the python-hpedockerplugin repository
  - $ cd ~
  - $ git clone -b k8s_cluster_vagrant https://github.com/saranke/hpe3par_test_automation.git
  - $ cd hpe3par_test_automation
  - Modify config/config.yml and provide master and worker nodes IPs, k8s version and http/https/no-proxy settings.

## Steps to create cluster:
- After setting up prerequisites, execute below command to create single-master k8s cluster.
  - $ cd hpe3par_test_automation
  - $ vagrant up [ vagrant up --debug to enable debug logs]

## Automated test execution:

  ### Prerequisite:
  - Disable strick host checking for ansible, set below env variable:
  - $ export ANSIBLE_HOST_KEY_CHECKING=False
  - Docker volume plugin must be installed on all nodes. (Please follow [steps](https://github.com/hpe-storage/python-hpedockerplugin/tree/master/ansible_3par_docker_plugin))
  - Execute install_libs.yml to setup ssh connectivity between k8s cluster nodes for execution of automation test. Modify hosts accordingly.
  - $ ansible-playbook -i hosts install_libs.yml
    > NOTE: hosts is needed as node-ips are fetched from the same.

  ### Steps for Automation Test Execution:
    - ssh to master node disabling StrickHostKeyChecking
      - $ ssh -o StrictHostKeyChecking=no master_node_ip
    - Clone test automation 
      - $ git clone -b k8s_auto https://github.com/saranke/hpe3par_test_automation.git
    - $ cd hpe3par_test_automation
    - $ pytest -s
