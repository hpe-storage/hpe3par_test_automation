#!/bin/sh

base=$(pwd)
echo "=================== In $base ==================="

echo "=================== Fetch existing installation name ==================="
helm_install_name="$(helm ls -n hpe-storage | awk 'NR==2 {print$1}')"
echo $helm_install_name

echo "=================== Calculate latest build# ==================="
latest_build=0
build_list=$(curl -s https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/ | awk '{print$2}' |awk -F'[^0-9]*' '$0=$2')

latest_build=$(printf "%s\n" ${build_list[@]} | sort -nr | head -1)
echo "=================== latest build is $latest_build ==================="

echo "=================== Clone co-deployment ==================="
rm -rf co-deployments external-snapshotter
git clone https://github.com/hpe-storage/co-deployments.git
cd co-deployments/helm/charts/hpe-csi-driver/templates
rm -f hpe-csi-controller.yaml hpe-csi-node.yaml hpe-nimble-csp.yaml hpe-primera-3par-csp.yaml


echo "=================== copy yamls from latest build to co-deployment ==================="
wget "https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/helm/hpe-csi-controller.yaml"
wget "https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/helm/hpe-csi-node.yaml"
wget "https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/helm/hpe-nimble-csp.yaml"
wget "https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/helm/hpe-primera-3par-csp.yaml "
wget "https://sjcartifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/helm/values.yaml"

echo "=================== mv values.yaml from template to up ==================="
cd ..
rm -f values.yaml
mv templates/values.yaml .

echo "=================== Uninstall existing driver ==================="
helm uninstall $helm_install_name -n hpe-storage

echo "=================== Cleanup all CRDs ==================="
kubectl delete hpenodeinfos.storage.hpe.com --all
kubectl delete hpereplicationdeviceinfos.storage.hpe.com --all
kubectl delete hpesnapshotgroupinfos.storage.hpe.com --all   
kubectl delete hpevolumegroupinfos.storage.hpe.com --all     
kubectl delete hpevolumeinfos.storage.hpe.com --all          
kubectl delete snapshotgroupclasses.storage.hpe.com --all     
kubectl delete snapshotgroupcontents.storage.hpe.com --all   
kubectl delete snapshotgroups.storage.hpe.com --all          
kubectl delete volumegroupclasses.storage.hpe.com --all      
kubectl delete volumegroupcontents.storage.hpe.com --all      
kubectl delete volumegroups.storage.hpe.com --all  
kubectl delete volumesnapshotcontents.snapshot.storage.k8s.io --all 
kubectl delete volumesnapshots.snapshot.storage.k8s.io          --all 
kubectl delete volumesnapshotclasses.snapshot.storage.k8s.io  --all


kubectl delete crd hpenodeinfos.storage.hpe.com
kubectl delete crd hpereplicationdeviceinfos.storage.hpe.com
kubectl delete crd hpesnapshotgroupinfos.storage.hpe.com    
kubectl delete crd hpevolumegroupinfos.storage.hpe.com      
kubectl delete crd hpevolumeinfos.storage.hpe.com           
kubectl delete crd snapshotgroupclasses.storage.hpe.com     
kubectl delete crd snapshotgroupcontents.storage.hpe.com    
kubectl delete crd snapshotgroups.storage.hpe.com           
kubectl delete crd volumegroupclasses.storage.hpe.com       
kubectl delete crd volumegroupcontents.storage.hpe.com      
kubectl delete crd volumegroups.storage.hpe.com           
kubectl delete crd volumesnapshotclasses.snapshot.storage.k8s.io
kubectl delete crd volumesnapshotcontents.snapshot.storage.k8s.io
kubectl delete crd  volumesnapshots.snapshot.storage.k8s.io

echo "=================== Install snapshot crds ==================="
cd $base
git clone https://github.com/kubernetes-csi/external-snapshotter
cd external-snapshotter
git checkout release-4.1
kubectl apply -f client/config/crd -f deploy/kubernetes/snapshot-controller 

echo "=================== sleep for 20 seconds before installation ==================="
sleep 20 

echo "=================== Install driver ==================="
helm install hpe-csi-driver $base/co-deployments/helm/charts/hpe-csi-driver --namespace hpe-storage

