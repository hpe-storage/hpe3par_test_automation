import pytest
import hpe_3par_kubernetes_manager as manager
import time
import yaml
import logging 
import globals


def test_volume_mutator_usrCPG():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        cpg = yaml_values['cpg']
 
        body = { 'metadata': { 'annotations': { 'csi.hpe.com/cpg' : cpg} } }

        #Edit pvc userCPG value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s usrCPG::%s" % (base_volume['name'],base_volume['userCPG']))
        assert cpg == base_volume['userCPG'], "Pvc userCPG edit failed for volume %s" %vol_name         

        
        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_volume_mutator_snapCPG():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_snpCPG.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        snpCPG = yaml_values['snpCpg']

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/snapCpg' : snpCPG} } }

        #Edit pvc snapCPG value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s usrCPG::%s" % (base_volume['name'],base_volume['userCPG']))
        assert snpCPG == base_volume['snapCPG'], "Pvc snapCPG edit failed for volume %s" %vol_name



        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_snpCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)



def test_volume_mutator_desc():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_desc.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        description = yaml_values['comment']

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/description' : description} } }

        #Edit pvc snapCPG value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s comment::%s" % (base_volume['name'],base_volume['comment']))
        assert description == base_volume['comment'], "Pvc description edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_desc :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)



def test_volume_mutator_Usr_SnpCPG():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_usr_snpCPG_desc.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        snpCPG = yaml_values['snpCpg']
        cpg = yaml_values['cpg']
        comment = yaml_values['comment']

        body = { 'metadata': { 'annotations': {'csi.hpe.com/cpg': cpg, 'csi.hpe.com/snapCpg' : snpCPG }}} 

        #Edit pvc snapCPG, cpg and comment values
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(20)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s usrCPG::%s" % (base_volume['name'],base_volume['userCPG']))
        assert snpCPG == base_volume['snapCPG'], "Pvc snapCPG edit failed for volume %s" %vol_name
        assert cpg == base_volume['userCPG'], "Pvc userCPG edit failed for volume %s" %vol_name
        #assert comment == base_volume['comment'], "Pvc description edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_usr_snpCPG_desc :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)


@pytest.mark.skip_array("3par")
def test_volume_mutator_provType_reduce():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_reduce.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] == 6, "Pvc provisional type edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_reduce :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc, pvc, pod)


@pytest.mark.skip_array("3par")
def test_volume_mutator_provType_tpvv():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_tpvv.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
			 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']

        body = { 'metadata': { 'annotations': {
	      'csi.hpe.com/provisioningType' : provType }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==2, "Pvc provisional type edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_reduce :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)




@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_tpvv_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_tpvv_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound', namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']

        body = { 'metadata': { 'annotations': {
				      'csi.hpe.com/provisioningType' : provType }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==2, "Pvc provisional type edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_reduce :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)


@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_full_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_full_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==1, "Pvc provisional type edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_full :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)


@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_dedup_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_dedup_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==6, "Pvc provisional type edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_dedup :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)


@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_dedup_compr_disable_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_dedup_compr_disable_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']
        compression = yaml_values['compression']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType,
                                      'csi.hpe.com/compression' : compression }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==2, "Pvc provisional type edit failed for volume %s" %vol_name
        assert base_volume['compressionState'] ==1, "Pvc compression edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_tpvv_compr :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)



@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_tpvv_compr_disable_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_tpvv_compr_disable_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']
        compression = yaml_values['compression']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType,
                                      'csi.hpe.com/compression' : compression }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==2, "Pvc provisional type edit failed for volume %s" %vol_name
        assert base_volume['compressionState'] ==2, "Pvc compression edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_dedup_tpvv_disable :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)







@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_dedup_compr_disable_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_dedup_compr_disable_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']
        compression = yaml_values['compression']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType,
                                      'csi.hpe.com/compression' : compression }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==6, "Pvc provisional type edit failed for volume %s" %vol_name
        assert base_volume['compressionState'] ==2, "Pvc compression edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_dedup_compr_disable :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)




@pytest.mark.skip_array("primera")
def test_volume_mutator_provType_dedup_compr_3par():
    base_yml = '%s/volume_mutator/vol-mutator-base-vol_provType_dedup_compr_3par.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        provType = yaml_values['provType']
        compression  = yaml_values['compression']

        body = { 'metadata': { 'annotations': {
                                      'csi.hpe.com/provisioningType' : provType,
                                      'csi.hpe.com/compression' : compression }}}

        #Edit provisionig type value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s provType::%s" % (base_volume['name'],base_volume['provisioningType']))
        assert base_volume['provisioningType'] ==6, "Pvc provisional type edit failed for volume %s" %vol_name
        assert base_volume['compressionState'] ==1, "Pvc compression state edit failed for volume %s" %vol_name


        # Export base volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_dedup_compr :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, pod)


def test_volume_mutator_differentDomain():
    base_yml = '%s/volume_mutator/vol-mutator-diff-domain.yml' % globals.yaml_dir
    timeout = 900
    sc = None
    pvc = None
    pod = None
    #Creating storage class and pvc
    try:
        sc = manager.create_sc(base_yml)
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)


        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info("Volume properties before edit in crd, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        yaml_values = manager.get_details_for_volume(base_yml)
        cpg = yaml_values['cpg']

        body = { 'metadata': { 'annotations': { 'csi.hpe.com/cpg' : cpg} } }

        #Edit pvc userCPG value
        patched_pvc_obj = manager.patch_pvc(pvc.metadata.name,globals.namespace,body)
        time.sleep(10)
        base_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)

        logging.getLogger().info("Volume properties after edit on array, name::%s usrCPG::%s" % (base_volume['name'],base_volume['userCPG']))
        assert cpg != base_volume['userCPG'], "Pvc userCPG edit failed for volume %s" %vol_name

    except Exception as e:
        logging.getLogger().error("Exception in test_volume_mutator_provType_dedup_compr :: %s" % e)
        cleanup(sc,pvc,pod)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        #cleanup(None, sc_snap, snap_pvc_obj, snap_pod_obj)
        cleanup(sc, pvc, None)







def cleanup(sc, pvc, pod):
    logging.getLogger().info("====== cleanup :START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)

       # "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC",None) is False:
        manager.delete_sc(sc.metadata.name)
    logging.getLogger().info("====== cleanup :END =========")

