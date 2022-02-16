#!/bin/sh

base=$(pwd)
echo "=================== In $base ==================="

echo "=================== Calculate latest build# ==================="
latest_build=0
build_list=$(curl -s https://dcs-docker.artifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/ | awk '{print$2}' |awk -F'[^0-9]*' '$0=$2')

latest_build=$(printf "%s\n" ${build_list[@]} | sort -nr | head -1)
echo "=================== latest build is $latest_build ==================="

echo "=================== Clone co-deployment ==================="
rm -rf co-deployments external-snapshotter
git clone https://github.com/hpe-storage/co-deployments.git
cd co-deployments/operators/hpe-csi-operator/deploy/
sed -i'' -e 's/my-hpe-csi-driver-operator/hpe-csi/g' scc.yaml
rm -f operator.yaml crds/storage.hpe.com_hpecsidrivers_crd.yaml crds/storage.hpe.com_v1_hpecsidriver_cr.yaml


echo "=================== copy yamls from latest build to co-deployment ==================="
wget "https://dcs-docker.artifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/operator/operator.yaml"
wget "https://dcs-docker.artifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/operator/storage.hpe.com_hpecsidrivers_crd.yaml" -P crds
wget "https://dcs-docker.artifactory.eng.nimblestorage.com/artifactory/dcs_k8s-local/co-deployments_master/$latest_build/operator/storage.hpe.com_v1_hpecsidriver_cr.yaml" -P crds


echo "=================== Cleanup existing build ==================="
oc delete hpenodeinfos.storage.hpe.com --all
oc delete hpereplicationdeviceinfos.storage.hpe.com --all
oc delete hpesnapshotgroupinfos.storage.hpe.com --all   
oc delete hpevolumegroupinfos.storage.hpe.com --all     
oc delete hpevolumeinfos.storage.hpe.com --all          
oc delete snapshotgroupclasses.storage.hpe.com --all     
oc delete snapshotgroupcontents.storage.hpe.com --all   
oc delete snapshotgroups.storage.hpe.com --all          
oc delete volumegroupclasses.storage.hpe.com --all      
oc delete volumegroupcontents.storage.hpe.com --all      
oc delete volumegroups.storage.hpe.com --all  
oc delete volumesnapshotcontents.snapshot.storage.k8s.io --all 
oc delete volumesnapshots.snapshot.storage.k8s.io          --all 
oc delete volumesnapshotclasses.snapshot.storage.k8s.io  --all

oc delete -f crds/storage.hpe.com_v1_hpecsidriver_cr.yaml
oc delete -f operator.yaml
oc delete -f crds/storage.hpe.com_hpecsidrivers_crd.yaml
oc delete -f service_account.yaml
oc delete -f role_binding.yaml
oc delete -f role.yaml
oc delete -f scc.yaml


echo "=================== Install snapshot crds ==================="
cd $base
git clone https://github.com/kubernetes-csi/external-snapshotter
cd external-snapshotter
git checkout release-4.1
oc apply -f client/config/crd -f deploy/kubernetes/snapshot-controller 


echo "=================== Install latest build ==================="
cd $base/co-deployments/operators/hpe-csi-operator/deploy/
oc create -f scc.yaml
oc create -f role.yaml
oc create -f role_binding.yaml
oc create -f service_account.yaml
oc create -f crds/storage.hpe.com_hpecsidrivers_crd.yaml 
oc create -f operator.yaml 
oc create -f crds/storage.hpe.com_v1_hpecsidriver_cr.yaml -n hpe-csi
