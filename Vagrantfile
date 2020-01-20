require 'yaml'
IMAGE_NAME = "centos/7"

# load config
configs = YAML.load_file("config/config.yaml")
#print configs
provisioned = false
Vagrant.configure("2") do |config|
    config.ssh.insert_key = false

    config.vm.provider "virtualbox" do |v|
        v.memory = 8192 
        v.cpus = 2
    end
 
    #print "\nCreating master node..."
    config.vm.define "k8s-master" do |master|
        master.vm.box = IMAGE_NAME
        master.vm.network "private_network", ip: configs['master_node_ip']
        master.vm.hostname = "k8s-master"
		
        master.proxy.http = configs['http_proxy']
        master.proxy.https = configs['https_proxy']
        master.proxy.no_proxy = configs['no_proxy']

		
        master.vm.provision "ansible" do |ansible|
            ansible.playbook = "kubernetes-setup/master-playbook.yml"
            ansible.verbose = "vvv"
            ansible.extra_vars = {
                node_ip: configs['master_node_ip'],
            }
            provisioned = true
        end
    end

    configs['worker_node_ips'].each_with_index do |val,index|
        node_ind = index + 1
        config.vm.define "node-#{node_ind}" do |node|
            #print "\nCreating "+ "node-#{node_ind} :: "+val
            node.vm.box = IMAGE_NAME
            node.vm.network "private_network", ip: val
            node.vm.hostname = "node-#{node_ind}"
			
            node.proxy.http = configs['http_proxy']
            node.proxy.https = configs['https_proxy']
            node.proxy.no_proxy = configs['no_proxy']
		
            node.vm.provision "ansible" do |ansible|
                ansible.playbook = "kubernetes-setup/node-playbook.yml"
                ansible.verbose = "vvv"
                ansible.extra_vars = {
                    node_ip: val,
                }
                provisioned = true
	    end
        end
    end

end

