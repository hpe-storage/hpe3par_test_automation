import functools
import os
import os.path
import random
import tarfile
import tempfile
import time

import docker
import pytest

def vol_random_name():
    return u'docker_{0:x}'.format(random.getrandbits(32))

def sc_random_name():
    return u'sc-{0:x}'.format(random.getrandbits(32))

def pv_random_name():
    return u'pv-{0:x}'.format(random.getrandbits(32))

def pvc_random_name():
    return u'pvc-{0:x}'.format(random.getrandbits(32))

def pod_random_name():
    return u'pod-{0:x}'.format(random.getrandbits(32))
