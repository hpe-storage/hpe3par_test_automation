import os
import shutil
import unittest

import docker
from docker.utils import kwargs_from_env
import six

from . import helpers


#### 
#
#   Base class file for Integration Tests for Docker Volume Plugin
####

BUSYBOX = 'busybox:buildroot-2014.02'
TEST_API_VERSION = os.environ.get('DOCKER_TEST_API_VERSION')


class BaseIntegrationTest(unittest.TestCase):
    """
    A base class for integration test cases. It cleans up the Docker server
    after itself.
    """

    def setUp(self):
        if six.PY2:
            self.assertRegex = self.assertRegexpMatches
            self.assertCountEqual = self.assertItemsEqual
        self.tmp_imgs = []
        self.tmp_containers = []
        self.tmp_folders = []
        self.tmp_volumes = []
        self.tmp_networks = []
        self.tmp_plugins = []
        self.tmp_secrets = []
        self.tmp_configs = []

    def tearDown(self):
        client = docker.from_env(version=TEST_API_VERSION)
        for img in self.tmp_imgs:
            try:
                client.remove_image(img)
            except docker.errors.APIError:
                pass
        for container in self.tmp_containers:
            try:
                client.remove_container(container, force=True)
            except docker.errors.APIError:
                pass
        for network in self.tmp_networks:
            try:
                client.remove_network(network)
            except docker.errors.APIError:
                pass
        for volume in self.tmp_volumes:
            try:
                client.remove_volume(volume)
            except docker.errors.APIError:
                pass

        for secret in self.tmp_secrets:
            try:
                client.remove_secret(secret)
            except docker.errors.APIError:
                pass

        for config in self.tmp_configs:
            try:
                client.remove_config(config)
            except docker.errors.APIError:
                pass

        for folder in self.tmp_folders:
            shutil.rmtree(folder)
