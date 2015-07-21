import log
import xml.etree.ElementTree as etree

# Base XmlNode to handle attr setting and hooks


class XmlNode:

    def __init__(self, xml_node):

        # set instance variables for all xml attrs
        for attr, val in xml_node.items():
            # allow subclasses to modify the attrs without having to override
            new_attr, new_val = self.before_attr_hook(attr, val)
            setattr(self, new_attr, new_val)

    # subclasses override this method to modify attr values
    # default returns the values unmodified
    def before_attr_hook(self, attr, val):
        return attr, val

    # returns the attrs set in __init__
    def items(self):
        def is_member(attr):
            return not callable(attr) and not attr.startswith("__")
        attrs = dir(self)
        return {attr: getattr(self, attr) for attr in attrs if is_member(attr)}


# Container for the node list, provides some find methods
class HostList:

    def __init__(self, host_nodes, logger=log.NoneLogger()):
        self.logger = logger
        self.nmap_hosts = map(lambda host: NmapNost(host, logger), host_nodes)

    def get_hosts(self):
        return self.nmap_hosts

    # Method to search for hosts
    # Predicate can either be a dict or a function
    # Dict: returns hosts where all dict keys/vals match an object
    # Function: returns hosts where the function evaluates to True
    def where(self, predicate):
        def shallow_compare(obj, comp):
            return all(getattr(obj, key) == val for key, val in comp.items())
        hosts = self.get_hosts()
        if type(predicate) is dict:
            return filter(lambda host: shallow_compare(host, predicate), hosts)
        elif type(predicate) is function:
            return filter(predicate, hosts)
        else:
            raise ArgumentError("Predicate must be either function or dict")

    # Method to search for hosts by port
    def find_by_port(self, port):
        def has_port(host):
            services = host.services
            return any(service.portid == str(port) for service in services)
        return self.where(has_port)


# Container for a host - attrs are set by default in XmlNode.__init__
class NmapHost(XmlNode):

    def __init__(self, host_node, logger=log.NoneLogger()):
        self.logger = logger
        XmlNode.__init__(self, host_node)
        for address in host_node.iter("address"):
            addr_type = address.get("addrtype")
            msg = ""
            if addr_type == "mac":
                msg = "[*] The host was on the same broadcast domain"
            elif addr_type == "ipv4":
                msg = "[*] The host had an IPv4 address"
            elif addr_type == "ipv6":
                msg = "[*] The host had an IPv6 address"
            self.logger.debug(msg)
            addr = address.get("addr")
            setattr(self, addr_type, addr)
        try:
            hostname_node = host_node.find("hostnames").find("hostname")
            self.hostname = hostname_node.get("name")
        except:
            self.logger.info("[*] No hostname found")
            self.hostname = None
        port_nodes = host_node.iter("port")
        self.services = [NmapService(port, self.logger) for port in ports]


# Container for a service - attrs are set by default in XmlNode.__init__
class NmapService(XmlNode):

    def __init__(self, service_node, logger=log.NoneLogger()):
        self.logger = logger
        XmlNode.__init__(self, service_node)


# Alternative parsing method - returns a HostList with the results
def parse2(nmap_xml_filename, logger=log.NoneLogger()):
    logger.info("[*] Parsing the Nmap XML file: %s" % nmap_xml_filename)
    tree = etree.parse(nmap_xml_filename)
    root = tree.getroot()
    return HostList(root.iter("host"), logger)


def parse(nmap_xml_filename, logger=log.NoneLogger()):
    if not nmap_xml_filename:
        msg = """[!] Cannot open Nmap XML file: %s
                 [-] Ensure that your are passing the correct file and format"""
        raise ArgumentError(msg % nmap_xml_filename)
    try:
        tree = etree.parse(nmap_xml_filename)
    except:
        msg = """"[!] Cannot open Nmap XML file: %s
                  [-] Ensure that your are passing the correct file and format"""
        raise ArgumentError(msg % (nmap_xml_filename))
    hosts = []
    services = []
    hostname_list = []
    root = tree.getroot()
    hostname_node = None
    logger.info("[*] Parsing the Nmap XML file: %s" % (nmap_xml_filename))
    for host in root.iter('host'):
        hostname = "Unknown hostname"
        for addresses in host.iter('address'):
            hwaddress = "No MAC Address ID'd"
            ipv4 = "No IPv4 Address ID'd"
            addressv6 = "No IPv6 Address ID'd"
            temp = addresses.get('addrtype')
            if "mac" in temp:
                hwaddress = addresses.get('addr')
                logger.debug("[*] The host was on the same broadcast domain")
            if "ipv4" in temp:
                address = addresses.get('addr')
                logger.debug("[*] The host had an IPv4 address")
            if "ipv6" in temp:
                addressv6 = addresses.get('addr')
                logger.debug("[*] The host had an IPv6 address")
        try:
            hostname_node = host.find('hostnames').find('hostname')
        except:
            logger.info("[!] No hostname found")
        if hostname_node is not None:
            hostname = hostname_node.get('name')
        else:
            hostname = "Unknown hostname"
            logger.info("[*] The hosts hostname is %s" % (str(hostname_node)))
        hostname_list.append(hostname)
        for item in host.iter('port'):
            state = item.find('state').get('state')
            # if state.lower() == 'open':
            service = item.find('service').get('name')
            protocol = item.get('protocol')
            port = item.get('portid')
            services.append([hostname_list, address, protocol, port, service, hwaddress, state])
    hostname_list = []
    for i in range(0, len(services)):
        service = services[i]
        index = len(service) - 1
        hostname = str1 = ''.join(service[0])
        address = service[1]
        protocol = service[2]
        port = service[3]
        serv_name = service[4]
        hwaddress = service[5]
        state = service[6]
        hosts[i] = [hostname, address, protocol, port, serv_name, hwaddress, state]
        logger.debug("[+] Adding %s with an IP of %s:%s with the service %s" % (hostname, address, port, serv_name))
    if hosts:
        logger.debug("[*] Results from NMAP XML import: ")
        for key, entry in self.hosts.iteritems():
            logger.debug("[*] %s" % (str(entry)))
        logger.info("[+] Parsed and imported unique ports %s" % (str(i+1)))
    else:
        logger.info("[-] No ports were discovered in the NMAP XML file")
