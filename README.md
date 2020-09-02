
# CVP GETARP Python Script

Even though this script is best effort supported, please send any issues you find, suggestions for improvements etc to: [ralf@arista.com](mailto:ralf@arista.com).  Please use the subject: **CVP GETARP**

This tool can be used to retireve the ARP Table from CVP instread of an EOS device.

Tested with CVP Versions 2019, 2020.1 2020.1.1

Below is an explanation of all command line options to `cvp_getarp.py`:

```
  -h --help            show this help message and exit
  -c CVPHOST, --cvphost CVPHOST
                        CVP host name FQDN or IP
  -u USER, --user USER  CVP username
  -p PASSWD, --password PASSWD
                        <cvpuser> password
  -d TARGETDEV, --device TARGETDEV
                        Target Devices IP(s) or Device hostname(s), -d
                        leaf1[,leaf2]
  -x INTERFACE --exclude INTERFACE
                        Exclude an specific interface on device=TARGETDEV
  -a TARGETARP, --arp TARGETARP
                        ARP address to be checked. If omitted all ARP entries will be showm.
  -v {1,2}, --verbose {1,2}
                        Verbose level 1 or 2 (just for debugging purposes)


```

Thx, Ralf Korschner, Systems Engineer Arista Networks

