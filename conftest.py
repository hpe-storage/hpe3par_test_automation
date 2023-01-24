import pytest
import hpe_3par_kubernetes_manager as manager
import yaml
import logging
import globals
import base64
import time

#LOGGER = logging.getLogger(__name__)

array_ip = None
protocol = None
hpe3par_version = None
hpe3par_cli = None
access_protocol = None
namespace = None
secret_dir = None
platform = None
yaml_dir = None
enc_secret = None


def pytest_addoption(parser):
    parser.addoption("--backend", action="store")#, default="0.0.0.0")
    parser.addoption("--access_protocol", action="store")
    parser.addoption("--namespace", action="store", default="hpe-storage")
    parser.addoption("--secret_dir", action="store")
    parser.addoption("--platform", action="store", help="Valid values k8s/os", default="k8s")
    parser.addoption("--username", action="store")
    parser.addoption("--password", action="store")


def pytest_configure(config):
    global array_ip, access_protocol, namespace, secret_dir, platform, yaml_dir
    if config.getoption("backend"):
        array_ip = config.getoption("backend")
    if config.getoption("access_protocol"):
        access_protocol = config.option.access_protocol
        globals.access_protocol = access_protocol
    if config.getoption("namespace"):
        namespace = config.option.namespace
        globals.namespace = namespace
    if config.getoption("secret_dir"):
        secret_dir = config.option.secret_dir
    if config.getoption("platform"):
        platform = config.option.platform
        globals.platform = platform
    if config.getoption("username"):
        username = config.option.username
        globals.username = username
    if config.getoption("password"):
        password = config.option.password
        globals.password = encodePwd(password)

    print("globals.replication_test :: %s" % globals.replication_test)
    if globals.replication_test is False:
        if secret_dir is None and array_ip is None:
            logging.getLogger().info("Please provide either of backend or secret_dir in command line")
            pytest.exit("Please provide either of backend or secret_dir in command line.")
        if secret_dir is not None and array_ip is not None:
            pytest.exit("Specifing both backend and secret_dir is not allowed. "
                        "Please provide either of backend or secret_dir in command line.")
    if platform is None or (platform.lower() != 'k8s' and platform.lower() != 'os'):
        pytest.exit("Must specify platform. Valid values are k8s/os.")

    # Get OS and pick yamls directory accordingly
    if platform.lower() == 'k8s':
        yaml_dir = 'yaml'
    elif platform.lower() == 'os':
        yaml_dir = 'yaml'

    globals.yaml_dir = yaml_dir





    #print("config.option.backend: " % config.getoption("backend"))
"""
def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    #option_value = metafunc.config.option.backend
    print("In pytest_generate_tests()")
    print(metafunc.config.getoption("backend"))
    print(metafunc.config.getoption("protocol"))
    print(metafunc.config.getoption("namespace"))
    global array_ip, array_uname, array_pwd, protocol, namespace
    if metafunc.config.getoption("backend"):
        array_ip = metafunc.config.option.backend
    if metafunc.config.getoption("protocol"):
        protocol = metafunc.config.option.protocol
    # metafunc.parametrize("name", [option_value])
"""


@pytest.fixture(scope="session")
def start():
    global hpe3par_version, array_ip 
    #LOGGER.info("%s %s "% (hpe3par_version[0:5], array_ip))
    logging.getLogger().info("%s %s " % (hpe3par_version[0:5], array_ip))


def encodePwd(password):
    pwd = password.encode(globals.encoding)
    password = base64. b64encode(pwd)
    return password


@pytest.fixture(scope="session", autouse=True)
def secret():
    global enc_secret
    password = (globals.password).decode(globals.encoding)
    if globals.encryption_test:
        enc_secret()
    if globals.replication_test is False :
        yml = None
        global array_ip,access_protocol, hpe3par_version, hpe3par_cli, namespace, secret_dir
        #if array_ip is None or namespace is None or access_protocol is None:
        if secret_dir is not None:
            yml = "%s/secret.yml" % secret_dir
            array_ip, globals.username, password = manager.read_array_prop(yml)
            logging.getLogger().info("Did not find backend, protocol and namespace in command line, picking from %s" % yml)

        logging.getLogger().info("Backend :: %s, namespace :: %s" % (array_ip, namespace))
        hpe3par_cli = manager.get_3par_cli_client(array_ip, globals.username, password)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        globals.hpe3par_cli = hpe3par_cli
        globals.hpe3par_version = hpe3par_version
        logging.getLogger().info('=============================== Test Automation START ========================')
        logging.getLogger().info("Array :: %s [%s] " % (array_ip, hpe3par_version[0:5]))

        """logging.error("\n########################### test_publish::%s::%s###########################" %
                      (protocol, hpe3par_version))"""
        if yml is None:
            yml = "{'apiVersion': 'v1', " \
                  "'kind': 'Secret', " \
                  "'metadata': {'name': 'ci-primera3par-csp-secret', 'namespace': %s}, " \
                  "'stringData': {'serviceName': 'primera3par-csp-svc', 'servicePort': '8080', " \
                                "'backend': %s, 'username': %s}, " \
                  "'data': {'password': %s}}" % (namespace, array_ip, globals.username, password)
            secret = manager.hpe_create_secret_object(yaml.safe_load(yml))
        else:
            secret = manager.create_secret(yml, globals.namespace)
    yield
    if globals.replication_test is False :
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        hpe3par_cli.logout()
    if globals.encryption_test:
        manager.delete_secret(enc_secret.metadata.name, enc_secret.metadata.namespace)
        pass



#@pytest.fixture(scope="function", autouse=True)
def enc_secret():
        global enc_secret
        yml = "yaml/enc_secret.yml"

        enc_secret = manager.create_secret(yml, globals.namespace)
        logging.getLogger().info("enc_secret :: %s " % enc_secret)


@pytest.fixture(scope="function", autouse=True)
def print_name(request):
    logging.getLogger().info("########################## Executing " + request.module.__name__ + "::" + request.function.__name__ +
                             " ################################")


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    test_summary = open("test_summary.log", "w")
    test_summary.write("-------- Test Summary ----------\n")
    total_cases = 0
    deselected_test = 0
    for key in terminalreporter.stats.keys():
        if key != '' and key != 'warnings':
            total_cases += len(terminalreporter.stats[key])
            test_summary.write(f"Test {key} :: {len(terminalreporter.stats[key])}\n")
        if key == 'deselected':
            deselected_test += len(terminalreporter.stats[key])

    test_summary.write(f"Total Test Executed :: {total_cases-deselected_test}\n")

    duration = time.time() - terminalreporter._sessionstarttime
    test_summary.write(f"Test duration:: {duration} seconds")
    test_summary.close()
