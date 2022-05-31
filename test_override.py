import pytest
import hpe_3par_kubernetes_manager as manager
import time
import yaml
import logging
import globals
from time import sleep


def test_override_usrCPG():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))
        assert cpg_name != vol_cpg, "Override of user_cpg parameter failed for %s" % vol_name    

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "userCPG does not match ovveride cpg parameter"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_InvalidUsrCPG():
    base_yml = '%s/override/invalid_ovverride_prop.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is False, "PVC %s in bound state with invalid user_cpg parameter %s " % (base_pvc_obj.metadata.name, cpg_name)
        logging.getLogger().info("Pvc not in bound state as ovverride user_cpg parameter is invalid :: %s" % base_pvc_obj.metadata.name)

    except Exception as e:
        logging.getLogger().error("Exception in test_override_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_and_expand_volume():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)

        assert cpg_name != vol_cpg, "Override failed for %s" % vol_name
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "userCPG does not match ovveride cpg parameter"

        # proceed to expanding pvc
        size_in_gb = '30'
        patch_json = {'spec': {'resources': {'requests': {'storage': size_in_gb + 'Gi'}}}}
        mod_pvc = manager.patch_pvc(pvc.metadata.name, pvc.metadata.namespace, patch_json)
        logging.getLogger().info("Patched PVC %s" % mod_pvc)
        sleep(20)

        # Creating pod
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

        # Now check if volume in 3par has increased size
        volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert volume['sizeMiB'] == int(size_in_gb) * 1024, "Volume on array does not have updated size"

        # Check if PVC has increaded size
        mod_pvc = manager.hpe_read_pvc_object(pvc.metadata.name, pvc.metadata.namespace)
        logging.getLogger().info("PVC after expansion %s" % mod_pvc)
        assert mod_pvc.spec.resources.requests['storage'] == "%sGi" % size_in_gb, "PVC %s does not have updated size" % pvc.metadata.name
                

    except Exception as e:
        logging.getLogger().error("Exception in test_override_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_snapCPG():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert snap_cpg != vol_snpCpg, "Override of snap_cpg parameter failed for %s" % vol_name
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['snapCPG'] == vol_snpCpg, "snapCPG does not match ovveride snap_cpg parameter"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_snapCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)



def test_override_description():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert desc != vol_desc, "Override of description parameter failed for volume %s" % vol_name
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['comment'] == vol_desc, "Descrition does not match ovveride description parameter"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_description :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_compression():
    if int(globals.hpe3par_version[0:1]) >= 4:
        pytest.skip("Skipped on Primera/Alletra array")
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        sc = manager.create_sc(base_yml)
        edit_yml_values(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)

        assert compression != vol_compr,"Override of compression parameter failed for %s" % vol_name
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['compressionState'] == 2, "compressionState does not match ovveride compression parameter"
        # (compressionState is set to 1 if compression is enabled on 3PAR volume)
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_compression :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_provType():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert provisioning != vol_provType, "Override of provision type parameter failed for %s" % vol_name
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['provisioningType'] == 2, "provisioningType does not match ovveride provision type parameter" # provisioningType is set to 6 if provisioningType is set to tdvv on 3PAR volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_provType :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_accessProtocol():
    #sc_yml = '%s/override/sc_ap_override.yaml' % globals.yaml_dir
    #pvc_yml = '%s/override/pvc_ap_override.yaml' % globals.yaml_dir
    #pod_yml = '%s/override/pod_ap_override.yaml' % globals.yaml_dir
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Editing storage class and pvc yaml
        edit_yml_values(base_yml)

  
        # Creating sc  
        sc = manager.create_sc(base_yml)

        # Reading sc parameter values from yaml 
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get pvc access protocol override property
        assert base_pvc_obj.metadata.annotations['csi.hpe.com/accessProtocol'] != accessProtocol, \
               "failed to ovverride access protocol parameter"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_accessProtocol :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_multiParam_sanity():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert cpg_name != vol_cpg, "Ovveride of user_cpg parameter failed"
        assert snap_cpg != vol_snpCpg, "Ovveride of snap_cpg parameter failed"
        assert desc != vol_desc, "Ovveride of description parameter failed"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "userCPG does not match ovveride cpg parameter"
        assert hpe3par_volume['snapCPG'] == vol_snpCpg, "snapCPG does not match ovveride snap_cpg parameter"
        assert hpe3par_volume['comment'] == vol_desc, "description does not match ovveride comment parameter"

        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_multiParam :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_reduce():
    if int(globals.hpe3par_version[0:1]) == 3:
        pytest.skip("Skipped on 3PAR array")
    base_yml = '%s/override/reduce_override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert provisioning != vol_provType, "Override of provisioning type parameter failed for primera array"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['provisioningType'] == 6, "provisioning type values does not match type on the array" # provisioningType is set to 6 if provisioningType is set to tdvv on 3PAR volume
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_reduce :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_emptyCPG():
    base_yml = '%s/override/emptyCPG_override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert vol_cpg is not None, "Failed to override user_cpg parameter when value is not specified in sc yaml"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "UserCpg does not match usr_cpg value on array"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_emptyCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_emptysnapCPG():
    base_yml = '%s/override/emptysnapCPG_override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert vol_snpCpg is not None, "Failed to override snap_cpg parameter when value is not specified in sc yaml"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))
        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['snapCPG'] == vol_snpCpg, "SnapCpg does not match snap_cpg value on array"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_emptysnapCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)


def test_override_cpgDomain():
    base_yml = '%s/override/cpgDomain_override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert cpg_name != vol_cpg, "Failed to ovveride user cpg parameter, outside default domain"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "userCPG parameter falied to match cpg value on array"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)



def test_override_cpgNoDomain():
    base_yml = '%s/override/cpgNoDomain_override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
        edit_yml_values(base_yml)
        sc = manager.create_sc(base_yml)
        provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol =  get_sc_properties(base_yml)
        logging.getLogger().info(
            "Volume properties set in SC, provisioning::%s compression::%s CPG::%s SNAP CPG::%s desc::%s Protocol::%s" % (
                provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol))
        pvc = manager.create_pvc(base_yml)
        flag, base_pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % base_pvc_obj.metadata.name
        logging.getLogger().info("Pvc in bound state :: %s" % base_pvc_obj.metadata.name)

        #Get pvc crd details
        pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_desc,vol_compr = manager.get_pvc_editable_properties(pvc_crd)
        assert cpg_name != vol_cpg, "Override of cpg parameter failed"
        logging.getLogger().info(
            "Overriden Volume properties, name::%s usrCPG::%s snpCPG::%s provType::%s compr::%s desc::%s" % (
            vol_name,vol_cpg,vol_snpCpg,vol_provType,vol_compr,vol_desc))

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        assert hpe3par_volume['userCPG'] == vol_cpg, "UserCPG values does nto match user_cpg value on array"
        pod = manager.create_pod(base_yml)
        flag, pod_obj = manager.check_status(timeout, pod.metadata.name, kind='pod', status='Running',
                                             namespace=pod.metadata.namespace)
        assert flag is True, "Pod %s status check timed out, not in Running state yet..." % pod.metadata.name

    except Exception as e:
        logging.getLogger().error("Exception in test_override_usrCPG :: %s" % e)
        raise e

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(sc,pvc,pod)



def cleanup(sc, pvc, pod):
    logging.getLogger().info("====== cleanup :START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod",
                                                    namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC",
                                                    namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)

    # "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC", None) is False:
        manager.delete_sc(sc.metadata.name)
    logging.getLogger().info("====== cleanup :END =========")


def get_sc_properties(yml):
    try:
        provisioning = None
        compression = None
        cpg_name = None
        snap_cpg = None
        desc = None
        accessProtocol = None
        with open(yml) as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                # print("======== kind :: %s " % str(el.get('kind')))
                if str(el.get('kind')) == "StorageClass":
                    if 'provisioning_type' in el['parameters']:
                        provisioning = el['parameters']['provisioning_type']
                    if 'compression' in el['parameters']:
                        compression = el['parameters']['compression']
                    if 'cpg' in el['parameters']:
                        cpg_name = el['parameters']['cpg']
                    if 'snapCpg' in el['parameters']:
                        snap_cpg = el['parameters']['snapCpg']
                    if 'description' in el['parameters']:
                        desc = el['parameters']['description']
                    if 'accessProtocol' in el['parameters']:
                        accessProtocol = el['parameters']['accessProtocol']
        logging.getLogger().info("provisioning :: %s, compression :: %s, cpg_name :: %s" % (provisioning, compression, cpg_name))
        return provisioning, compression, cpg_name, snap_cpg, desc, accessProtocol
    except Exception as e:
        logging.getLogger().error("Exception in get_sc_properties :: %s" % e)
        raise e


def edit_yml_values(yml):
    try:
        pvc_accessProtocol = None
        accessProtocol = None
        with open(yml, 'r') as f:
            elements = list(yaml.safe_load_all(f))
            for el in elements:
                if str(el.get('kind')) == "StorageClass" and \
                    'accessProtocol' in el['parameters']:                    
                        if globals.access_protocol  == 'fc':
                            el['parameters']['accessProtocol'] = 'iscsi'
                        else:
                            el['parameters']['accessProtocol'] = 'fc'


                if str(el.get('kind')) == "PersistentVolumeClaim" and \
                    'csi.hpe.com/accessProtocol' in el['metadata']['annotations']:
                     el['metadata']['annotations']['csi.hpe.com/accessProtocol'] = globals.access_protocol
                

        with open(yml, 'w') as out:
           yaml.dump_all(elements, out, default_flow_style=False, sort_keys=False)
        logging.getLogger().info("Edit of sc and pvc access protocol values in sc and pvc yaml successfull")
    except Exception as e:
        logging.getLogger().error("Exception in editing yaml properties :: %s" % e)
        raise e

