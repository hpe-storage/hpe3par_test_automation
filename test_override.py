import pytest
import hpe_3par_kubernetes_manager as manager
import time
import yaml
import logging
import globals


def test_override_usrCPG():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
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

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        if cpg_name != vol_cpg:
            if (hpe3par_volume['userCPG']) == vol_cpg:
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


def test_override_snapCPG():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
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

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        if snap_cpg != vol_snpCpg:
            if (hpe3par_volume['snapCPG']) == vol_snpCpg:
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



def test_override_description():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
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

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        if desc != vol_desc:
            if (hpe3par_volume['comment']) == vol_desc:
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



def test_override_compression():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
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

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        if compression != vol_compr:
            if (hpe3par_volume['compressionState']) == 1: # compressionState is set to one of compression is enabled on 3PAR volume
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


def test_override_provType():
    base_yml = '%s/override/override.yaml' % globals.yaml_dir
    timeout = globals.status_check_timeout
    sc = None
    pvc = None
    pod = None
    try:
        # Creating storage class and pvc
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

        # Get proprties from the array
        hpe3par_volume = manager.get_volume_from_array(globals.hpe3par_cli, vol_name)
        if provisioning != vol_provType:
            if (hpe3par_volume['provisioningType']) == 6: # provisioningType is set to 6 if provisioningType is set to tdvv on 3PAR volume
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
