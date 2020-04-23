kubectl delete statefulset snapshot-controller &
helm uninstall  hpe-csi -n kube-system &
kubectl delete crd --all &
sleep 30
#pwd
export http_proxy=http://web-proxy.in.hpecorp.net:8080
export https_proxy=http://web-proxy.in.hpecorp.net:8080
export ftp_proxy=http://web-proxy.in.hpecorp.net:8080
echo "test automation has been started"
git clone https://github.com/saranke/hpe3par_test_automation.git -b csi_k8s_test_automation
cd hpe3par_test_automation
mv YAML YAML_old 
mv YAML_FC_4.1 YAML
rm -rf .pytest_cache __pycache__
#cp -rf /root/vishal_automation/* .
#pwd
#cd new_approach
helm install hpe-csi hpe-csi-driver-2.0.0-beta.tgz -f values_3par.yaml -n kube-system
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/master/config/crd/snapshot.storage.k8s.io_volumesnapshotclasses.yaml
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/master/config/crd/snapshot.storage.k8s.io_volumesnapshotcontents.yaml
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/master/config/crd/snapshot.storage.k8s.io_volumesnapshots.yaml
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/master/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml &
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/master/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml &
sleep 120
