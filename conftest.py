import ipaddress
import pytest
import hpe_3par_kubernetes_manager as manager
import yaml
import logging
import globals
import base64
import time
import hpe3parclient
from packaging import version
import re

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
hpe3par_model = None


def pytest_addoption(parser):
    parser.addoption("--backend", action="store")#, default="0.0.0.0")
    parser.addoption("--access_protocol", action="store")
    parser.addoption("--namespace", action="store", default="hpe-storage")
    parser.addoption("--secret_dir", action="store")
    parser.addoption("--platform", action="store", help="Valid values k8s/os", default="k8s")
    parser.addoption("--username", action="store")
    parser.addoption("--password", action="store")
    parser.addoption("--csi-version", action="store", default=None,
                        help="Filter tests based on CSI version (e.g., '>=2.4.0', '<=2.5.0', '==2.4.2')")
    parser.addoption("--workernode_password", action="store", default="Nim123Boli")

def pytest_configure(config):
    global array_ip, access_protocol, namespace, secret_dir, platform, yaml_dir
    config.addinivalue_line(
        "markers", "csi(version): mark test for specified CSI version"
    )
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
    if config.getoption("workernode_password"):
        workernode_password = config.option.workernode_password
        globals.workernode_password = workernode_password

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
        global array_ip,access_protocol, hpe3par_version, hpe3par_cli, hpe3par_model, namespace, secret_dir
        #if array_ip is None or namespace is None or access_protocol is None:
        if secret_dir is not None:
            yml = "%s/secret.yml" % secret_dir
            array_ip, globals.username, password = manager.read_array_prop(yml)
            logging.getLogger().info("Did not find backend, protocol and namespace in command line, picking from %s" % yml)

        logging.getLogger().info("Backend :: %s, namespace :: %s" % (array_ip, namespace))
        hpe3par_cli = manager.get_3par_cli_client(array_ip, globals.username, password)
        hpe3par_version = manager.get_array_version(hpe3par_cli)
        hpe3par_model, is_primera = manager.get_array_model(hpe3par_cli)
        globals.hpe3par_cli = hpe3par_cli
        globals.hpe3par_version = hpe3par_version
        if is_primera is True:
            if "HPE_3PAR" in hpe3par_model:
                globals.hpe3par_model = "Primera"
            elif "HPE Alletra Storage MP" in hpe3par_model:
                globals.hpe3par_model = "Arcus"
            elif "HPE Alletra" in hpe3par_model:
                globals.hpe3par_model = "Alletra"
        elif "HPE_3PAR" in hpe3par_model:
            globals.hpe3par_model = "3PAR"
        else:
            logging.getLogger().info("Could not parse array's model")
            pytest.exit("Please provide supported array model. Could not parse array's model")
        logging.getLogger().info('=============================== Test Automation START ========================')
        logging.getLogger().info("Array :: %s [%s] Model :: [%s]" % (array_ip, hpe3par_version[0:5], globals.hpe3par_model))

        """logging.error("\n########################### test_publish::%s::%s###########################" %
                      (protocol, hpe3par_version))"""
        if yml is None:
            yml = "{'apiVersion': 'v1', " \
                  "'kind': 'Secret', " \
                  "'metadata': {'name': 'ci-primera3par-csp-secret', 'namespace': %s}, " \
                  "'stringData': {'serviceName': 'primera3par-csp-svc', 'servicePort': '8080', " \
                                "'backend': %s, 'username': %s}, " \
                  "'data': {'password': %s}}" % (namespace, array_ip, globals.username, password)
            ip = array_ip
            if "[" in array_ip and "]" in array_ip:
                ip = array_ip.strip("[]")
            if _check_ip_version(ip) == 'IPv6':
                yml = yml.replace(
                    "'backend': %s" % array_ip,
                    "'backend': '%s'" % array_ip)
            secret = manager.hpe_create_secret_object(yaml.safe_load(yml))
        else:
            secret = manager.create_secret(yml, globals.namespace)
    yield
    if globals.replication_test is False :
        manager.delete_secret(secret.metadata.name, secret.metadata.namespace)
        try:
            hpe3par_cli.logout()
        except hpe3parclient.exceptions.HTTPForbidden as e:
            logging.getLogger().info("Exception in hpe3par_cli.logout, session could have timeout already: %s" % e)
            pass
    if globals.encryption_test:
        manager.delete_secret(enc_secret.metadata.name, enc_secret.metadata.namespace)
        pass

def _check_ip_version(ip):
    """Check if the given IP address is IPv4 or IPv6.
    
    Args:
        ip (str): The IP address to check.
    Returns:
        str: 'IPv4' if the IP is IPv4, 'IPv6' if the IP is IPv6, 'Unknown' otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "IPv4"
        else:
            return "IPv6"
    except ValueError:
        return "Invalid IP"

@pytest.fixture(scope="module", autouse=True)
def create_domain_and_cpgs():
    
    domain_names = ['test_domain', 'test_domain_1']
    cpg_names_with_domains = {
        'CI_CPG_test_domain': 'test_domain',
        'CI_CPG_test_domain_2': 'test_domain_1'
        }
    cpg_names_no_domain = ['k8s_auto_test', 'multidomain_cpg', 'CI_CPG']
    password = (globals.password).decode(globals.encoding)
    hpe3par_cli = manager.get_3par_cli_client(array_ip, globals.username, password)    

    try:
        for domain_name in domain_names:
            try:
                # response = manager.create_domain(hpe3par_cli, domain_name) #createdomain is not available
                logging.getLogger().info("Failed to create domain, Create Domains manually: %s" % domain_name)
            except Exception as e:
                logging.getLogger().error("Error during domain creation for: %s. Exception: %s" % (domain_name, e))
                raise
    
        # Create CPGs with domains to simulate different storage configurations for testing purposes
        for cpg_name, domain in cpg_names_with_domains.items():
            try:
                options = {'domain': domain}
                response = manager.create_cpg_in_array(hpe3par_cli, cpg_name, options=options)
                logging.getLogger().info("CPG creation operation successfully completed for: %s under domain: %s" % (cpg_name, domain))
            except Exception as e:
                logging.getLogger().error("Error during CPG creation operation for CPG: %s under domain: %s. Exception encountered: %s" % (cpg_name, domain, e))
                raise

        # Create CPGs without domains
        for cpg_name in cpg_names_no_domain:
            try:
                options = {}
                response = manager.create_cpg_in_array(hpe3par_cli, cpg_name, options=options)
                logging.getLogger().info("CPG creation operation successfully completed for: %s with no domain" % cpg_name)
            except Exception as e:
                logging.getLogger().error("Error during CPG creation for: %s with no domain. Exception: %s" % (cpg_name, e))
                raise

    except Exception as e:
                logging.getLogger().error("Error during domain or CPG creation: %s" % str(e))
                raise

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


def _parse_version_condition(condition_str):
    """Parse version condition string like '>=2.4.0', '<=2.5.0', '==2.4.2'
    
    Returns:
        tuple: (operator, version_obj) or None if invalid
    """
    if not condition_str:
        return None
        
    # Match operators: >=, <=, ==, >, <, =
    pattern = r'^(>=|<=|==|>|<|=)(.+)$'
    match = re.match(pattern, condition_str.strip())
    
    if not match:
        # If no operator, assume exact match
        try:
            return ('==', version.parse(condition_str.strip()))
        except:
            return None
    
    operator, version_str = match.groups()
    try:
        version_obj = version.parse(version_str.strip())
        # Convert single = to ==
        if operator == '=':
            operator = '=='
        return (operator, version_obj)
    except:
        return None

def _version_matches_condition(test_version_str, condition):
    """Check if test version matches the condition
    
    Args:
        test_version_str: Version string from test marker
        condition: Tuple of (operator, version_obj)
    
    Returns:
        bool: True if version matches condition
    """
    if not condition:
        return True
        
    operator, target_version = condition
    try:
        test_version = version.parse(test_version_str)
    except:
        return False
    
    if operator == '>=':
        return test_version >= target_version
    elif operator == '<=':
        return test_version <= target_version
    elif operator == '==':
        return test_version == target_version
    elif operator == '>':
        return test_version > target_version
    elif operator == '<':
        return test_version < target_version
    
    return False

def pytest_collection_modifyitems(config, items):
    csi_version_filter = config.getoption("--csi-version")
    
    if csi_version_filter:
        condition = _parse_version_condition(csi_version_filter)
        if condition:
            new_items = []
            for item in items:
                marker = item.get_closest_marker("csi")
                if marker and marker.kwargs.get("version"):
                    test_version = marker.kwargs["version"]
                    if _version_matches_condition(test_version, condition):
                        new_items.append(item)
            items[:] = new_items
        else:
            raise pytest.UsageError(
                f"Invalid --csi-version format: '{csi_version_filter}'. "
                f"Expected format: operator + version (e.g., '>=2.4.0', '<=2.5.0', '==2.4.2', '>2.3.0', '<2.6.0') "
                f"or just version for exact match (e.g., '2.4.2')"
            )

        
