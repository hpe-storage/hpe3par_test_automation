require 'yaml'
IMAGE_NAME = "centos/7"

# load config
configs = YAML.load_file("config/config.yaml")
#print configs
Vagrant.configure("2") do |config|
    config.ssh.insert_key = false

    config.vm.provider "virtualbox" do |v|
        v.memory = 2048
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

		
	if ENV['mode'] == 'cluster' 
            master.vm.provision "ansible" do |ansible|
                ansible.playbook = "kubernetes-setup/master-playbook.yml"
                ansible.verbose = "vvv"
                ansible.extra_vars = {
                    node_ip: configs['master_node_ip'],
                }
            end
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
		
	    if ENV['mode'] == 'cluster'
                node.vm.provision "ansible" do |ansible|
                    ansible.playbook = "kubernetes-setup/node-playbook.yml"
                    ansible.verbose = "vvv"
                    ansible.extra_vars = {
                        node_ip: val,
                   }
                end
	    end
        end
    end
	
	
    # Invoke ansible installer for plugin installation
    #if ENV['mode'] == 'plugin' 
    #    config.vm.provision "ansible" do |ansible|
    #        ansible.playbook = "../ansible_install_bhagyashree/install_hpe_3par_volume_driver.yml"
    #        ansible.inventory_path = "../ansible_installer_centos/hosts"
    #        ansible.limit = 'all'
    #        ansible.verbose = "vvv"
    #    end
    #end
	
    #print "\nNow executing test_automation"
    # install python dependencies for test automation
    #if ENV['mode'] == 'test_automation' 
    #    print "\nIn test_automation"
    #    config.vm.provision "ansible" do |ansible|
    #	    print "\nIn test_automation :: executing playbook"
    #        ansible.playbook = "../install_libs.yml"
    #        ansible.inventory_path = "../ansible_installer_centos/hosts"
    #        ansible.limit = 'all'
    #        ansible.verbose = "vvv"
    #    end
    #end

end

