import hpe_3par_kubernetes_manager as manager
from hpe3parclient.exceptions import HTTPBadRequest
from hpe3parclient.exceptions import HTTPForbidden
from hpe3parclient.exceptions import HTTPConflict
from hpe3parclient.exceptions import HTTPNotFound


def test_import_and_clone():
    base_yml = 'YAML/import_vol/import-vol-base-clone.yml'
    clone_yml = 'YAML/import_vol/import-vol-clone.yml'
    hpe3par_cli = None
    clone_pvc = None
    clone_pod_obj = None
    clone_pvc_obj = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        hpe3par_cli = manager.get_3par_cli_client(base_yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(base_yml), protocol, manager.get_array_version(hpe3par_cli)))
        # Create volume in 3par and import it to csi.
        print("Creating base volume in 3par and importing it to CSI for further cloning...")
        volume, secret, sc, pvc, pod = create_import_verify_volume(base_yml, hpe3par_cli, protocol, False, True)

        # Now create clone of imported volume
        print("Clone the imported volume...")
        clone_pvc = manager.create_pvc(clone_yml)
        flag, clone_pvc_obj = manager.check_status(None, clone_pvc.metadata.name, kind='pvc', status='Bound',
                                                   namespace=clone_pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, clone pvc for imported volume not in Bound state yet..." % \
                             clone_pvc_obj.metadata.name
        print("Cloned PVC is Bound")
        assert manager.verify_clone_crd_status(clone_pvc_obj.spec.volume_name) is True, \
            "Clone PVC CRD is not yet completed"
        print("Cloned PVC CRD is completed")
        clone_pvc_crd = manager.get_pvc_crd(clone_pvc_obj.spec.volume_name)
        # print(pvc_crd)
        clone_volume_name = manager.get_pvc_volume(clone_pvc_crd)

        # Now publish cloned pvc
        print("Publish cloned pvc...")
        clone_pod_obj = create_verify_pod(clone_yml, hpe3par_cli, clone_pvc_obj, clone_volume_name, protocol)

        # Delete all kinds now
        # delete_resources(hpe3par_cli, secret, sc, pvc, pod, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(None, None, clone_pvc_obj, clone_pod_obj)
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_import_cloned_vol():
    yml = 'YAML/import_vol/import-vol-base-clone2.yml'
    hpe3par_cli = None
    secret = None
    sc = None
    pvc_obj = None
    pod_obj = None
    try:
        # Create volume
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_import_cloned_vol test %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))

        yaml_values = manager.get_details_for_volume(yml)
        options = prepare_options(yaml_values, hpe3par_version)
        # Create volume in array to be cloned and later imported to csi
        vol_name = yaml_values['vol_name']
        volume = None
        volume, exception = create_vol_in_array(hpe3par_cli, options, vol_name=vol_name, size=yaml_values['size'],
                                                cpg_name=yaml_values['cpg'])
        # assert volume is not None, "Volume %s is not created on array as %s. Terminating test." % (vol_name, exception)
        if volume is None:
            print("Volume %s is not created on array as %s. Terminating test." % (vol_name, exception))
            return
        print("Volume %s created successfully on array. Now Create clone..." % volume['name'])
        clone_volume, message = create_clone_in_array(hpe3par_cli, source_vol_name=vol_name, option={'online': True, 'tpvv': True})
        print("Cloned volume is :: %s" % clone_volume)
        message = "Clone volume creation on array failed with error %s. Terminating test." % message
        assert clone_volume is not None, message
        clone_vol_name = clone_volume['name']

        # Now import base of the clone to csi
        secret = manager.create_secret(yml)
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        print("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        assert status == 'ProvisioningSucceeded', f"{message}"
        flag, pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s for base volume %s status check timed out, not in Bound state yet..." % \
                             (pvc_obj.metadata.name, vol_name)
        print("\n\nBase volume (after cloning at array) has been imported successfully to CSI.")

        # Compare imported volume object with old volume object on array
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        imported_volume_name = manager.get_pvc_volume(pvc_crd)
        csi_volume = manager.get_volume_from_array(hpe3par_cli, imported_volume_name)
        vol_has_diff, diff = compare_volumes(volume, csi_volume)
        assert vol_has_diff is False, "After import volume properties are changed. Modified properties are %s" % diff
        print("\nImported volume's properties have been verified successfully, all property values retain.")
        pod_obj = create_verify_pod(yml, hpe3par_cli, pvc_obj, imported_volume_name, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        delete_vol_from_array(hpe3par_cli, clone_vol_name)
        cleanup(secret, sc, pvc_obj, pod_obj)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_thin_true_comp_import_vol():
    yml = "YAML/import_vol/import-vol-thin-true-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_thin_false_comp_import_vol():
    yml = "YAML/import_vol/import-vol-thin-false-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_thin_absent_comp_import_vol():
    yml = "YAML/import_vol/import-vol-thin-absent-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_full_true_comp_import_vol():
    yml = "YAML/import_vol/import-vol-full-true-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_full_false_comp_import_vol():
    yml = "YAML/import_vol/import-vol-full-false-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_full_absent_comp_import_vol():
    yml = "YAML/import_vol/import-vol-full-absent-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_dedup_true_comp_import_vol():
    yml = "YAML/import_vol/import-vol-dedup-true-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_dedup_false_comp_import_vol():
    yml = "YAML/import_vol/import-vol-dedup-false-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_dedup_absent_comp_import_vol():
    yml = "YAML/import_vol/import-vol-dedup-absent-comp.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_diff_snap_usr_cpg_import_vol():
    yml = "YAML/import_vol/import-vol-diff_snap_usr_cpg.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_exp_ret_set_import_vol():
    yml = "YAML/import_vol/import-vol-exp-ret-set.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol)
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_diff_size_pvc_import_vol():
    yml = "YAML/import_vol/import-vol-diff-size-in-pvc.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    vol_name = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        yaml_values = manager.get_details_for_volume(yml)
        vol_name = yaml_values['vol_name']
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol, publish=False, pvc_bound=False,
                                                                                pvc_message=
                                                                                'differs in size given in pvc yml')
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        delete_vol_from_array(hpe3par_cli, vol_name)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_diff_domain_import_vol():
    yml = "YAML/import_vol/import-vol-in-domain.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc_obj = None
    pod = None
    secret_other_domain = None
    sc_other_domain = None
    pvc_other_domain = None
    pod_other_domain = None
    try:
        # Create PVC and mount to put this host in a domain
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_thin_false_comp_diff_domain_import_vol %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))
        secret = manager.create_secret(yml)
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        print("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        assert status == 'ProvisioningSucceeded', f"{message}"
        flag, pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name
        print("\n\nThin-False PVC created and Bound now will mount it to put host in domain")

        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        volume_name = manager.get_pvc_volume(pvc_crd)
        pod = create_verify_pod(yml, hpe3par_cli, pvc_obj, volume_name, protocol)
        print("Published done, host belong to domain now.\nImport a volume now from CPG belongs to different domain")
        diff_domain_yml = "YAML/import_vol/import-vol-thin-false-comp.yml"
        diff_domain_hpe3par_cli = manager.get_3par_cli_client(yml)
        diff_domain_array_ip, diff_domain_array_uname, diff_domain_array_pwd, diff_domain_protocol = manager.read_array_prop(diff_domain_yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(diff_domain_yml), diff_domain_protocol, manager.get_array_version(diff_domain_hpe3par_cli)))
        volume_other_domain, secret_other_domain, sc_other_domain, pvc_other_domain, pod_other_domain = \
            create_import_verify_volume(diff_domain_yml, diff_domain_hpe3par_cli, diff_domain_protocol, publish=True, pvc_bound=True, pod_run=False, pod_message=
            'Imported volume failed to publsh on different domain as expected.')

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc_obj, pod)
        cleanup(secret_other_domain, sc_other_domain, pvc_other_domain, pod_other_domain)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_import_vol_with_other_param():
    yml = "YAML/import_vol/import-vol-with-other-param.yml"
    hpe3par_cli = None
    secret = None
    sc = None
    pvc = None
    pod = None
    vol_name = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        yaml_values = manager.get_details_for_volume(yml)
        vol_name = yaml_values['vol_name']
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol, publish=False, pvc_bound=False,
                                                                                pvc_message=
                                                                                'storage class has different parameters set')
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        delete_vol_from_array(hpe3par_cli, vol_name)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_import_imported_volume():
    yml = "YAML/import_vol/import-vol-test-import-imported.yml"
    import_imported_volume(yml, False)


def test_import_exported_volume():
    yml = "YAML/import_vol/import-vol-test-import-exported.yml"
    import_imported_volume(yml, True)


def test_import_vol_starts_from_pvc():
    yml = "YAML/import_vol/import-vol-start-from-pvc.yml"
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol, False, False, pvc_message=
                                                                                'starts with string pvc')
        """status, message, secret, sc, pvc, pod = create_import_verify_volume(yml, False, False)
        assert status == 'ProvisioningFailed', "Imported volume name starts from pvc"
        print(message)"""

    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        if volume is not None:
            delete_vol_from_array(hpe3par_cli, volume['name'])
        cleanup(secret, sc, pvc, pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_import_snap_no_base():
    try:
        yml = "YAML/import_vol/import-vol-snap-no-base.yml"
        # Create volume
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_import_snap_no_base test %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))

        yaml_values = manager.get_details_for_volume(yml)
        options = prepare_options(yaml_values, hpe3par_version)
        # Create volume in array to be imported
        vol_name = yaml_values['vol_name']
        snap_volume = None
        volume = None
        volume, exception = create_vol_in_array(hpe3par_cli, options, vol_name=vol_name, size=yaml_values['size'], cpg_name=yaml_values['cpg'])
        # assert volume is not None, "Volume %s is not created on array as %s. Terminating test." % (vol_name, exception)
        if volume is None:
            print("Volume %s is not created on array as %s. Terminating test." % (vol_name, exception))
            return
        print("Volume %s created successfully on array. Now Create snapshot..." % volume['name'])
        snap_volume, message = create_snapshot_in_array(hpe3par_cli, None, snap_name='snap-of-%s' % vol_name, vol_name=vol_name)
        print("Snapshot volume is :: %s" % snap_volume)

        # Now import this snap volume to csi without importing base volume
        secret = manager.create_secret(yml)
        sc = manager.create_sc(yml)
        pvc = manager.create_pvc(yml)
        print("Check in events if volume is created...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
        assert status == 'ProvisioningFailed', "Imported snap volume %s without importing base %s)" % (snap_volume, vol_name)
        print("\n\nCould not import snap volume before importing base, as expected.")
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, None)
        delete_vol_from_array(hpe3par_cli, snap_volume['name'])
        delete_vol_from_array(hpe3par_cli, volume['name'])
        """if snap_volume is not None:
            hpe3par_cli.deleteVolume(snap_volume['name'])
        if volume is not None:
            hpe3par_cli.deleteVolume(volume['name'])"""
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def test_create_snap_import_both_publish_base():
    base_yml = "YAML/import_vol/import-vol-base-snap.yml"
    snap_yml = "YAML/import_vol/import-vol-snap-of-base.yml"
    create_vol_snap_import_publish(base_yml, snap_yml, mount_base='after_snap')


def test_create_snap_import_publish_base_import_snap():
    base_yml = "YAML/import_vol/import-vol-base-snap.yml"
    snap_yml = "YAML/import_vol/import-vol-snap-of-base.yml"
    create_vol_snap_import_publish(base_yml, snap_yml, mount_base='before_snap')


def test_snap_name_starts_with_snapshot():
    base_yml = "YAML/import_vol/import-vol-base-for-snap-start-with-snapshot.yml"
    snap_yml = "YAML/import_vol/import-vol-snap-name-start-with-snapshot.yml"
    create_vol_snap_import_publish(base_yml, snap_yml, first_snap_import='fail')


def create_vol_snap_import_publish(base_yml, snap_yml, first_snap_import='pass', create_second_snap=False, mount_base='after_snap'):
    base_secret = None
    base_sc = None
    base_pvc_obj = None
    base_pod = None
    snap_secret = None
    snap_sc = None
    snap_pvc = None
    snap_class_name = None
    snapshot_name = None
    try:
        # Create base volume
        hpe3par_cli = manager.get_3par_cli_client(base_yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(base_yml)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        print("\n########################### test_import_base_and_snap test %s::%s::%s ###########################" %
              (str(base_yml), protocol, hpe3par_version[0:5]))

        base_yaml_values = manager.get_details_for_volume(base_yml)
        base_options = prepare_options(base_yaml_values, hpe3par_version)
        # Create volume in array to be imported
        base_vol_name = base_yaml_values['vol_name']
        volume, exception = create_vol_in_array(hpe3par_cli, base_options, vol_name=base_vol_name, size=base_yaml_values['size'],
                                                cpg_name=base_yaml_values['cpg'])
        assert volume is not None, f"{exception}"
        """if volume is None:
            print("Volume %s is not created on array as %s. Terminating test." % (base_vol_name, exception))
            return"""
        # Now create snap volume and import
        print("\n\nVolume %s created successfully on array. Now Create snapshot..." % volume['name'])
        #snap_yml = "YAML/import_vol/import-vol-snap-of-base.yml"
        snap_yaml_values = manager.get_details_for_volume(snap_yml)
        snap_options = prepare_options(snap_yaml_values, hpe3par_version)

        # Create snapshot in array to be imported
        snap_vol_name = snap_yaml_values['vol_name']
        snap_volume, message = create_snapshot_in_array(hpe3par_cli, None, snap_name=snap_vol_name, vol_name=base_vol_name)
        print("Snapshot volume is :: %s" % snap_volume)

        # Import base volume to csi
        print("Importing base volume to CSI...")
        base_secret = manager.create_secret(base_yml)
        base_sc = manager.create_sc(base_yml)
        base_pvc = manager.create_pvc(base_yml)
        print("Check in events if volume is created...")
        base_status, base_message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=base_pvc.metadata.name,
                                                           namespace=base_pvc.metadata.namespace, uid=base_pvc.metadata.uid)
        assert base_status == 'ProvisioningSucceeded', f"{base_message}"
        print("\n\nImported base volume successfully to CSI, now import snap")

        # Publish base if is to be done before snapshot import
        if mount_base == 'before_snap':
            print("Now publish base volume that is imported to csi...")
            base_pvc_obj = manager.hpe_read_pvc_object(base_pvc.metadata.name, base_pvc.metadata.namespace)
            base_pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
            # print(pvc_crd)
            base_imported_volume_name = manager.get_pvc_volume(base_pvc_crd)
            base_pod = create_verify_pod(base_yml, hpe3par_cli, base_pvc_obj, base_imported_volume_name, protocol)
            print("Imported base volume is published successfully")

        # Import snap volume to csi
        print("Now importing snap to CSI...")
        #     Create snapclass
        print("Creating Snapclass now...")
        snap_class_yml = "YAML/import_vol/import-vol-snapshot-class.yml"
        snap_class_name = manager.get_kind_name(snap_class_yml, 'VolumeSnapshotClass')
        assert manager.create_snapclass(snap_class_yml, snap_class_name) is True, \
            'Snapclass %s is not created.' % snap_class_name
        print('Snapclass %s is created successfully.' % snap_class_name)
        assert manager.verify_snapclass_created(snap_class_name) is True, \
            'Snapclass %s is not found in crd list.' % snap_class_name
        print('Verified snapclass %s in crd list.' % snap_class_name)

        # Create snapshot
        print("Creating snapshot now...")
        snapshot_yml = "YAML/import_vol/import-vol-snapshot.yml"
        snapshot_name = manager.get_kind_name(snapshot_yml, 'VolumeSnapshot')
        assert manager.create_snapshot(snapshot_yml, snapshot_name) is True, 'Snapshot %s is not created.' % snapshot_name
        print('Snapshot %s is created successfully.' % snapshot_name)
        assert manager.verify_snapshot_created(snapshot_name) is True, 'Snapshot %s is not found in crd list.' % \
                                                                       snapshot_name
        print('Verified snapshot %s in crd list.' % snapshot_name)
        # Verify if snapshot ready to use
        flag, snap_uid = manager.verify_snapshot_ready(snapshot_name)
        if first_snap_import == 'fail':
            assert flag is False, "Snapshot %s is ready to use" % snapshot_name
            print("\n\nSnapshot %s creation failed as expected." % snapshot_name)
        else:
            assert flag is True, "Snapshot %s is not ready to use" % snapshot_name
            print('\n\nVerified snapshot %s is ready to use.' % snapshot_name)
            snap_pvc_uid = "snapshot-" + snap_uid
            csi_snap_volume = manager.get_volume_from_array(hpe3par_cli, snap_pvc_uid[0:31])
            vol_has_diff, diff = compare_volumes(snap_volume, csi_snap_volume)
            assert vol_has_diff is False, "After import snap volume properties are changed. Modified properties are %s" % \
                                          diff
            print("\nImported snapshot's properties have been verified successfully, all property values retain.")

        if mount_base == 'after_snap':
            print("Now publish base volume that is imported to csi...")
            base_pvc_obj = manager.hpe_read_pvc_object(base_pvc.metadata.name, base_pvc.metadata.namespace)
            base_pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
            # print(pvc_crd)
            base_imported_volume_name = manager.get_pvc_volume(base_pvc_crd)
            base_pod = create_verify_pod(base_yml, hpe3par_cli, base_pvc_obj, base_imported_volume_name, protocol)
            print("Imported base volume is published successfully")

        """snap_secret = manager.create_secret(snap_yml)
        snap_sc = manager.create_sc(snap_yml)
        snap_pvc = manager.create_pvc(snap_yml)
        print("Check in events if snap volume is created...")
        snap_status, snap_message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=snap_pvc.metadata.name,
                                                           namespace=snap_pvc.metadata.namespace, uid=snap_pvc.metadata.uid)
        assert snap_status == 'ProvisioningSucceeded', f"{snap_message}"
        print("\n\nImported snap volume successfully to CSI, now publish")

        # Publish base volume imported to csi
        flag, base_pvc_obj = manager.check_status(30, base_pvc.metadata.name, kind='pvc', status='Bound',
                                             namespace=base_pvc.metadata.namespace)
        base_pvc_crd = manager.get_pvc_crd(base_pvc_obj.spec.volume_name)
        # print(pvc_crd)
        base_imported_volume_name = manager.get_pvc_volume(base_pvc_crd)
        base_pod = create_verify_pod(
            base_yml, hpe3par_cli, base_pvc_obj, base_imported_volume_name, protocol)"""
    finally:
        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(snap_secret, snap_sc, snap_pvc, None)
        cleanup_crd(snapshot_name, snap_class_name)
        cleanup(base_secret, base_sc, base_pvc_obj, base_pod)
        if hpe3par_cli is not None:
            hpe3par_cli.logout()


def prepare_options(yaml_values, hpe3par_version):
    options = {}
    if 'comment' in yaml_values.keys():
        options['comment'] = yaml_values['comment']
    if 'snapCPG' in yaml_values.keys():
        options['snapCPG'] = yaml_values['snapCPG']
    if yaml_values['provisioning'] == "tpvv":
        options['tpvv'] = True
    if yaml_values['provisioning'] == "dedup":
        options['tdvv'] = True
    if yaml_values['provisioning'] == "reduce":
        options['tdvv'] = True
    if 'compression' in yaml_values.keys():
        if yaml_values['compression'] is True or yaml_values['compression'] == 'true':
            options['compression'] = True
        if yaml_values['compression'] is False or yaml_values['compression'] == 'false':
            options['compression'] = False
    return options


def import_imported_volume(yml, publish):
    secret = None
    sc = None
    pvc = None
    pod = None
    sc_with_imported_vol = None
    pvc_with_imported_vol = None
    try:
        hpe3par_cli = manager.get_3par_cli_client(yml)
        array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
        print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, manager.get_array_version(hpe3par_cli)))
        # Import volume for 1st time
        volume, secret, sc, pvc, pod = create_import_verify_volume(yml, hpe3par_cli, protocol, publish)

        print("SC :: %s\nPVC :: %s\nPOD :: %s" % (sc, pvc, pod))
        # Fetch name of the volume after import
        pvc_crd = manager.get_pvc_crd(pvc.spec.volume_name)
        # print(pvc_crd)
        imported_volume_name = manager.get_pvc_volume(pvc_crd)

        print("Modifying yml for storage class and pvc for import_vol and name")
        # Modify yml and provide renamed volume for import_vol param in sc
        yml_list = modify_in_mem_yml(yml, imported_volume_name)
        print("modified yml :: %s" % yml_list)

        pvc_with_imported_vol = None
        # Create sc and pvc
        for kind in yml_list:
            if str(kind.get('kind')) == 'StorageClass':
                sc_with_imported_vol = manager.hpe_create_sc_object(kind)
                print(sc_with_imported_vol)

            if str(kind.get('kind')) == 'PersistentVolumeClaim':
                pvc_with_imported_vol = manager.hpe_create_pvc_object(kind)
                print(pvc_with_imported_vol)

        print("PVC with imported volume :: %s " % pvc_with_imported_vol)
        print("Check in events if volume provisioning status...")
        status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc_with_imported_vol.metadata.name,
                                                           namespace=pvc_with_imported_vol.metadata.namespace, uid=pvc_with_imported_vol.metadata.uid)
        assert status != 'ProvisioningSucceeded', "Import succeeded for already imported volume %s" % imported_volume_name
        print("\n\nProvisioning failed for PVC with already imported volume %s. Error is %s " % (imported_volume_name,message))

        # Now cleanup secret, sc, pv, pvc, pod
        cleanup(secret, sc, pvc, pod)
        cleanup(None, sc_with_imported_vol, pvc_with_imported_vol, None)
    except Exception as e:
        print("Exception in test_import_imported_volume :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e
    finally:
        cleanup(secret, sc, pvc, pod)
        cleanup(None, sc_with_imported_vol, pvc_with_imported_vol, None)


def modify_in_mem_yml(yml, new_vol_name, suffix='new'):
    import yaml
    obj = None
    with open(yml) as f:
        elements = list(yaml.safe_load_all(f))
        for el in elements:
            # print("======== kind :: %s " % str(el.get('kind')))
            """if str(el.get('kind')) == to_be_modified['kind']:
                for key in to_be_modified.keys():
                    if key == 'kind':
                        continue
                    if len(key.keys()) == 0:
                        el[key] =  to_be_modified['kind'][key]
                    else:
                        for key1 in key.keys():
                            len(key1.keys()) == 0:
                e1['parameters']['importVol'] = to_be_modified['value']
                HPE3PAR_IP = el['stringData']['backend']
                # print("PersistentVolume YAML :: %s" % el)
                print("\nCreating StorageClass...")
                obj = hpe_create_sc_object(el)
                print("\nStorageClass %s created." % obj.metadata.name)"""
            if str(el.get('kind')) == 'StorageClass':
                el['parameters']['importVol'] = new_vol_name
                el['metadata']['name'] = el['metadata']['name'] + "-%s" % suffix
            if str(el.get('kind')) == 'PersistentVolumeClaim':
                el['spec']['storageClassName'] = el['spec']['storageClassName'] + "-%s" % suffix
                el['metadata']['name'] = el['metadata']['name'] + "-%s" % suffix
    return elements


def create_import_verify_volume(yml, hpe3par_cli, protocol, publish=True, pvc_bound=True, pvc_message='', pod_run=True, pod_message=''):
    secret = None
    sc = None
    pvc_obj = None
    pod_obj = None
    volume = None

    # Create volume
    """hpe3par_cli = manager.get_3par_cli_client(yml)
    array_ip, array_uname, array_pwd, protocol = manager.read_array_prop(yml)
    hpe3par_version = manager.get_array_version(hpe3par_cli)
    print("\n########################### Import volume test %s::%s::%s ###########################" %
              (str(yml), protocol, hpe3par_version[0:5]))"""
    hpe3par_version = manager.get_array_version(hpe3par_cli)
    yaml_values = manager.get_details_for_volume(yml)
    if yaml_values['provisioning'].lower() == 'full' and hpe3par_version[0:1] == '4':
        print("Full Provisioning not supported on primera. Terminating test.")
        return None, None, None, None, None
    options = prepare_options(yaml_values, hpe3par_version)
    # Create volume in array to be imported
    print("Options to 3par cli for creating volume :: %s " % options)
    volume, exception = create_vol_in_array(hpe3par_cli, options, vol_name=yaml_values['vol_name'],
                                            size=yaml_values['size'], cpg_name=yaml_values['cpg'])
    # assert volume is not None, "Volume %s is not created on array as %s. Terminating test." % (vol_name, exception)
    if volume is None:
        print("Volume %s is not created on array as %s. Terminating test." % (yaml_values['vol_name'], exception))
        return None, None, None, None, None
    print("Volume %s created successfully on array. Now import it to CSI..." % volume['name'])

    # Import volume now in CSI
    secret = manager.create_secret(yml)
    sc = manager.create_sc(yml)
    pvc = manager.create_pvc(yml)
    print("Check in events if volume is created...")
    status, message = manager.check_status_from_events(kind='PersistentVolumeClaim', name=pvc.metadata.name,
                                                           namespace=pvc.metadata.namespace, uid=pvc.metadata.uid)
    #print(status)
    #print(message)
    if pvc_bound:
        assert status == 'ProvisioningSucceeded', f"{message}"
        flag, pvc_obj = manager.check_status(30, pvc.metadata.name, kind='pvc', status='Bound',
                                                 namespace=pvc.metadata.namespace)
        assert flag is True, "PVC %s status check timed out, not in Bound state yet..." % pvc_obj.metadata.name

        # Compare imported volume object with old volume object on array
        pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print(pvc_crd)
        imported_volume_name = manager.get_pvc_volume(pvc_crd)
        csi_volume = manager.get_volume_from_array(hpe3par_cli, imported_volume_name)
        vol_has_diff, diff = compare_volumes(volume, csi_volume)
        assert vol_has_diff is False, "After import volume properties are changed. Modified properties are %s" % diff
        print("\nImported volume's properties have been verified successfully, all property values retain.")

    else:
        pvc_obj = pvc
        """assert status == 'ProvisioningFailed', "Imported volume that starts from PVC (%s)" % yaml_values['vol_name']
        print("\n\nCould not import volume starts with PVC, as expected.")"""
        assert status == 'ProvisioningFailed', "Imported volume that %s" % pvc_message
        print("\n\nCould not import volume %s, as expected." % pvc_message)
        # return status, "\n\nCould not import volume starts with PVC, as expected.", secret, pvc_obj, None

    # Now publish this volume and verify vluns
    if publish is True:
        pod_obj = create_verify_pod(yml, hpe3par_cli, pvc_obj, imported_volume_name, protocol, pod_run, pod_message)

    return volume, secret, sc, pvc_obj, pod_obj


def create_verify_pod(yml, hpe3par_cli, pvc_obj, imported_volume_name, protocol, pod_run=True, pod_message=''):
    pod = manager.create_pod(yml)
    flag, pod_obj = manager.check_status(None, pod.metadata.name, kind='pod', status='Running',
                                         namespace=pod.metadata.namespace)

    if pod_run:
        assert flag is True, "Published imported volume via pod %s, but it is not in Running state yet..." % pod.metadata.name
    else:
        assert flag is False
        print(pod_message)
        return pod_obj

    # Verify crd fpr published status
    assert manager.verify_pvc_crd_published(pvc_obj.spec.volume_name) is True, \
        "PVC CRD %s Published is false after Pod is running" % pvc_obj.spec.volume_name

    hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, imported_volume_name)
    assert manager.verify_pod_node(hpe3par_vlun, pod_obj) is True, \
        "Node for pod received from 3par and cluster do not match"

    # verify_vlun(hpe3par_cli, hpe3par_vlun, pod_obj, protocol)

    return pod_obj


def verify_vlun(hpe3par_cli, hpe3par_vlun, pod_obj, protocol):
    if protocol == 'iscsi':
        iscsi_ips = manager.get_iscsi_ips(hpe3par_cli)

        flag, disk_partition = manager.verify_by_path(iscsi_ips, pod_obj.spec.node_name)
        assert flag is True, "partition not found"
        print("disk_partition received are %s " % disk_partition)

        flag, disk_partition_mod = manager.verify_multipath(hpe3par_vlun, disk_partition)
        assert flag is True, "multipath check failed"
        print("disk_partition after multipath check are %s " % disk_partition)
        print("disk_partition_mod after multipath check are %s " % disk_partition_mod)
        assert manager.verify_partition(disk_partition_mod), "partition mismatch"

        assert manager.verify_lsscsi(pod_obj.spec.node_name, disk_partition), "lsscsi verificatio failed"


def compare_volumes(vol1, vol2):
    print("In compare_volumes()")
    print("vol1 :: %s" % vol1)
    print("vol2 :: %s" % vol2)

    flag = False
    diff_keys = {}
    try:
        for key, value in vol1.items():
            # if key == 'name' or key == 'links':
            #    continue
            if key not in ['deduplicationState', 'compressionState', 'provisioningType', 'copyType', 'wwn', 'userCPG',
                           'snapCPG']:
                continue
            if key in vol2 and vol1[key] != vol2[key]:
                diff_keys[key] = value
                flag = True

        return flag, diff_keys
    except Exception as e:
        print("Exception in compare_volumes :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def create_vol_in_array(hpe3par_cli, options, vol_name='test-importVol', cpg_name='CI_CPG', size=10240):
    try:
        print("In create_vol_in_array() :: vol_name :: %s, cpg_name :: %s, size :: %s, options :: %s" % (vol_name,
                                                                                                         cpg_name, size, options))
        response = hpe3par_cli.createVolume(vol_name, cpg_name, size, options)
        print("Create volume response %s" % response)
        volume = manager.get_volume_from_array(hpe3par_cli, vol_name)
        return volume, None
    except (HTTPConflict, HTTPBadRequest, HTTPForbidden) as e:
        print("Exception from create_vol_in_array :: %s " % e)
        return None, e
    except Exception as e:
        print("Exception in create_vol_in_array :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def create_snapshot_in_array(hpe3par_cli, options, snap_name='snap-test-importVol', vol_name='test-importVol'):
    try:
        print("In create_snapshot_in_array() :: snap_name :: %s, vol_name :: %s" % (snap_name, vol_name))
        response = hpe3par_cli.createSnapshot(snap_name, vol_name)
        print("Create volume response\n%s" % response)
        snap_volume = manager.get_volume_from_array(hpe3par_cli, snap_name)
        return snap_volume, None
    except (HTTPConflict, HTTPForbidden) as e:
        print("Exception from create_snapshot_in_array :: %s " % e)
        return None, e
    except Exception as e:
        print("Exception in create_snapshot_in_array :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def create_clone_in_array(hpe3par_cli, source_vol_name='test-importVol', dest_vol_name=None, dest_cpg='CI_CPG', option=None):
    try:
        if dest_vol_name is None or dest_vol_name == '':
            dest_vol_name = 'clone-%s' % source_vol_name
        print("In create_clone_in_array() :: source_vol_name :: %s, dest_vol_name :: %s, dest_cpg :: %s, option :: %s" %
              (source_vol_name, dest_vol_name, dest_cpg, option))
        response = hpe3par_cli.copyVolume(source_vol_name, dest_vol_name, dest_cpg, option)
        print("Create clone response\n%s" % response)
        clone_volume = manager.get_volume_from_array(hpe3par_cli, dest_vol_name)
        return clone_volume, None
    except (HTTPConflict, HTTPForbidden, HTTPBadRequest) as e:
        print("Exception from create_clone_in_array :: %s " % e)
        return None, e
    except Exception as e:
        print("Exception in create_clone_in_array :: %s" % e)
        #logging.


def delete_vol_from_array(hpe3par_cli, vol_name):
    try:
        print("In delete_vol_from_array() :: vol_name :: %s" % vol_name)
        volume = manager.get_volume_from_array(hpe3par_cli, vol_name)
        if volume is not None:
            hpe3par_cli.deleteVolume(vol_name)
    except (HTTPConflict, HTTPNotFound, HTTPForbidden) as e:
        print("Exception from delete_vol_from_array :: %s " % e)
    except Exception as e:
        print("Exception in delete_vol_from_array :: %s" % e)
        #logging.error("Exception in test_publish :: %s" % e)
        raise e


def cleanup(secret, sc, pvc, pod):
    print("====== cleanup :START =========")
    #logging.info("====== cleanup after failure:START =========")
    if pod is not None and manager.check_if_deleted(2, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is False:
        manager.delete_pod(pod.metadata.name, pod.metadata.namespace)
    if pvc is not None and manager.check_if_deleted(2, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is False:
        manager.delete_pvc(pvc.metadata.name)
        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
    if sc is not None and manager.check_if_deleted(2, sc.metadata.name, "SC") is False:
        manager.delete_sc(sc.metadata.name)
    if secret is not None and manager.check_if_deleted(2, secret.metadata.name, "Secret", namespace=secret.metadata.namespace) is False:
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
    print("====== cleanup :END =========")
    #logging.info("====== cleanup after failure:END =========")


def cleanup_crd(snapshot_name, snapclass_name):
    print("====== cleanup_crd :START =========")
    # logging.info("====== cleanup after failure:START =========")
    if snapshot_name is not None:# and manager.check_if_crd_deleted(snapshot_name, "volumesnapshots") is False:
        manager.delete_snapshot(snapshot_name)
    if snapclass_name is not None:# and manager.check_if_crd_deleted(snapclass_name, "volumesnapshotclasses") is False:
        manager.delete_snapclass(snapclass_name)
    print("====== cleanup_crd :END =========")
    # logging.info("====== cleanup after failure:END =========")


def delete_resources(hpe3par_cli, secret, sc, pvc, pod, protocol):
    timeout = 600
    try:
        assert manager.delete_pod(pod.metadata.name, pod.metadata.namespace), "Pod %s is not deleted yet " % \
                                                                              pod.metadata.name
        assert manager.check_if_deleted(timeout, pod.metadata.name, "Pod", namespace=pod.metadata.namespace) is True, \
            "Pod %s is not deleted yet " % pod.metadata.name

        pvc_crd = manager.get_pvc_crd(pvc.spec.volume_name)
        # print(pvc_crd)
        volume_name = manager.get_pvc_volume(pvc_crd)

        if protocol == 'iscsi':
            hpe3par_vlun = manager.get_3par_vlun(hpe3par_cli, volume_name)
            iscsi_ips = manager.get_iscsi_ips(hpe3par_cli)
            flag, disk_partition = manager.verify_by_path(iscsi_ips, pod.spec.node_name)
            flag, ip = manager.verify_deleted_partition(iscsi_ips, pod.spec.node_name)
            assert flag is True, "Partition(s) not cleaned after volume deletion for iscsi-ip %s " % ip

            paths = manager.verify_deleted_multipath_entries(pod.spec.node_name, hpe3par_vlun)
            assert paths is None or len(paths) == 0, "Multipath entries are not cleaned"

            # partitions = manager.verify_deleted_lsscsi_entries(pod_obj.spec.node_name, disk_partition)
            # assert len(partitions) == 0, "lsscsi verificatio failed for vlun deletion"
            flag = manager.verify_deleted_lsscsi_entries(pod.spec.node_name, disk_partition)
            print("flag after deleted lsscsi verificatio is %s " % flag)
            assert flag, "lsscsi verification failed for vlun deletion"

        # Verify crd for unpublished status
        try:
            assert manager.verify_pvc_crd_published(pvc.spec.volume_name) is False, \
                "PVC CRD %s Published is true after Pod is deleted" % pvc.spec.volume_name
            print("PVC CRD published is false after pod deletion.")
            # logging.warning("PVC CRD published is false after pod deletion.")
        except Exception as e:
            print("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
            # logging.error("Resuming test after failure of publishes status check for pvc crd... \n%s" % e)
        assert manager.delete_pvc(pvc.metadata.name)

        assert manager.check_if_deleted(timeout, pvc.metadata.name, "PVC", namespace=pvc.metadata.namespace) is True, \
            "PVC %s is not deleted yet " % pvc.metadata.name

        # pvc_crd = manager.get_pvc_crd(pvc_obj.spec.volume_name)
        # print("PVC crd after PVC object deletion :: %s " % pvc_crd)
        assert manager.check_if_crd_deleted(pvc.spec.volume_name, "hpevolumeinfos") is True, \
            "CRD %s of %s is not deleted yet. Taking longer..." % (pvc.spec.volume_name, 'hpevolumeinfos')
        sleep(30)
        assert manager.verify_delete_volume_on_3par(hpe3par_cli, volume_name), \
            "Volume %s from 3PAR for PVC %s is not deleted" % (volume_name, pvc.metadata.name)

        assert manager.delete_sc(sc.metadata.name) is True

        assert manager.check_if_deleted(timeout, sc.metadata.name, "SC") is True, "SC %s is not deleted yet " \
                                                                                  % sc.metadata.name

        assert manager.delete_secret(secret.metadata.name, secret.metadata.namespace) is True

        assert manager.check_if_deleted(timeout, secret.metadata.name, "Secret",
                                        namespace=secret.metadata.namespace) is True, \
            "Secret %s is not deleted yet " % secret.metadata.name
    except Exception as e:
        print("Exception in delete_resource() :: %s " % e)
