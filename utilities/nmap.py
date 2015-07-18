import log
import xml.etree.ElementTree as etree

class XmlNode:


    def __init__(self, xml_node):
        for attr,val in xml_node.items():
            self.before_attr_hook(attr,val)
            setattr(self,attr,val)

    def before_attr_hook(self,attr,val):
        pass

    def items(self):
        return {attr:getattr(self,attr) for attr in dir(self) if not callable(attr) and not attr.startswith("__")}

class HostList:


    def __init__(self, host_nodes, logger=log.NoneLogger()):
        self.logger = logger
        self.nmap_hosts = [NmapHost(host_node, self.logger) for host_node in host_nodes]

    def get_hosts(self):
        return self.nmap_hosts

    def where(self, predicate):
        if type(predicate) is dict:
            return [host for host in self.get_hosts() if
                    all(getattr(host,key) == val for key,val in predicate.items())]
        elif type(predicate) is function:
            return [host for host in self.get_hosts() if predicate(host)]
        else:
            return []

    def find_by_port(self,port):
        return [host for host in self.get_hosts() if
                any(service.portid == str(port) for service in host.services)]

class NmapHost(XmlNode):


    def __init__(self, host_node, logger=log.NoneLogger()):
        self.logger = logger
        XmlNode.__init__(self, host_node)
        for address in host_node.iter("address"):
            addr_type = address.get("addrtype")
            if addr_type == "mac":
                self.logger.debug("[*] The host was on the same broadcast domain")
            elif addr_type == "ipv4":
                self.logger.debug("[*] The host had an IPv4 address")
            elif addr_type == "ipv6":
                self.logger.debug("[*] The host had an IPv6 address")
            addr = address.get("addr")
            setattr(self,addr_type,addr)
        try:
            hostname_node = host_node.find("hostnames").find("hostname")
            self.hostname = hostname_node.get("name")
        except:
            self.logger.info("[*] No hostname found")
            self.hostname = None
        self.services = [NmapService(port,self.logger) for port in  host_node.iter("port")]


class NmapService(XmlNode):


    def __init__(self, service_node, logger=log.NoneLogger()):
        self.logger = logger
        XmlNode.__init__(self, service_node)

def parse2(nmap_xml_filename, logger=log.NoneLogger()):
    logger.info("[*] Parsing the Nmap XML file: %s" % nmap_xml_filename)
    tree = etree.parse(nmap_xml_filename)
    root = tree.getroot()
    return HostList(root.iter("host"),logger)



def parse(nmap_xml_filename, logger=log.NoneLogger()):
    if not nmap_xml_filename:
        raise ArgumentError("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (nmap_xml_filename))
    try:
        tree = etree.parse(nmap_xml_filename)
    except:
        raise ArgumentError("[!] Cannot open Nmap XML file: %s \n[-] Ensure that your are passing the correct file and format" % (nmap_xml_filename))
    hosts=[]
    services=[]
    hostname_list=[]
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
            #if state.lower() == 'open':
            service = item.find('service').get('name')
            protocol = item.get('protocol')
            port = item.get('portid')
            services.append([hostname_list, address, protocol, port, service, hwaddress, state])
    hostname_list=[]
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
        logger.debug("[+] Adding %s with an IP of %s:%s with the service %s"%(hostname,address,port,serv_name))
    if hosts:
        logger.debug("[*] Results from NMAP XML import: ")
        for key, entry in self.hosts.iteritems():
            logger.debug("[*] %s" % (str(entry)))
        logger.info("[+] Parsed and imported unique ports %s" % (str(i+1)))
    else:
        logger.info("[-] No ports were discovered in the NMAP XML file")
