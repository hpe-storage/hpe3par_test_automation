import pytest
import hpe_3par_kubernetes_manager as manager
import yaml
import logging
import globals

#LOGGER = logging.getLogger(__name__)

array_ip = None
array_uname = None
array_pwd = None
protocol = None
hpe3par_version = None
hpe3par_cli = None
access_protocol = None
namespace = None
secret_dir = None
platform = None
yaml_dir = None


def pytest_addoption(parser):
    print("Adding command line options")
    parser.addoption("--backend", action="store")#, default="0.0.0.0")
    parser.addoption("--access_protocol", action="store", default="iscsi")
    parser.addoption("--namespace", action="store", default="hpe-storage")
    parser.addoption("--secret_dir", action="store")
    parser.addoption("--platform", action="store", help="Valid values k8s/os", default="k8s")
    """parser.addoption("backend", dest='backend')
    parser.addoption("protocol", dest='protocol')
    parser.addoption("namespace", dest='namespace')"""


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

    if secret_dir is None and array_ip is None:
        logging.getLogger().info("Please provide either of backend or yaml_dir in command line")
        pytest.exit("Please provide either of backend or yaml_dir in command line.")
    if secret_dir is not None and array_ip is not None:
        pytest.exit("Specifing both backend and secret_dir is not allowed. "
                    "Please provide either of backend or secret_dir in command line.")
    if platform is None or (platform.lower() != 'k8s' and platform.lower() != 'os'):
        pytest.exit("Must specify platform. Valid values are k8s/os.")

    # Get OS and pick yamls directory accordingly
    if platform.lower() == 'k8s':
        yaml_dir = 'yaml_k8s'
    elif platform.lower() == 'os':
        yaml_dir = 'yaml_os'

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
    if metafunc.config.getoption("namespace"):
        namespace = metafunc.config.option.namespace
    # metafunc.parametrize("name", [option_value])
"""


@pytest.fixture(scope="session")
def start():
    global hpe3par_version, array_ip
    #LOGGER.info("%s %s "% (hpe3par_version[0:5], array_ip))
    logging.getLogger().info("%s %s " % (hpe3par_version[0:5], array_ip))


@pytest.fixture(scope="session", autouse=True)
def secret():
    yml = None
    global array_ip, array_uname, array_pwd, access_protocol, hpe3par_version, hpe3par_cli, namespace, secret_dir
    #if array_ip is None or namespace is None or access_protocol is None:
    if secret_dir is not None:
        yml = "%s/secret.yml" % secret_dir
        array_ip, array_uname, array_pwd = manager.read_array_prop(yml)
        logging.getLogger().info("Did not find backend, protocol and namespace in command line, picking from %s" % yml)

    logging.getLogger().info("Backend :: %s, namespace :: %s" % (array_ip, namespace))
    hpe3par_cli = manager.get_3par_cli_client(array_ip)
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
              "'data': {'password': %s}}" % (namespace, array_ip, '3paradm', 'M3BhcmRhdGE=')
        secret = manager.hpe_create_secret_object(yaml.load(yml))
    else:
        secret = manager.create_secret(yml)
    yield
    manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
    hpe3par_cli.logout()


@pytest.fixture(scope="function", autouse=True)
def print_name(request):
    logging.getLogger().info("########################## Executing " + request.module.__name__ + "::" + request.function.__name__ +
                             " ################################")


"""
@pytest.fixture(scope="function")
def array_details():
    global hpe3par_version, array_ip
    logging.getLogger().info("array_details is fetched")


@pytest.fixture(scope="function")
def hpe3par_cli():
    global hpe3par_cli
    logging.getLogger().info("hpe3par_cli is fetched")
    return hpe3par_cli


@pytest.fixture(scope="function")
def access_protocol():
    global access_protocol
    return access_protocol


@pytest.fixture(scope="function")
def namespace():
    global namespace
    return namespace """
