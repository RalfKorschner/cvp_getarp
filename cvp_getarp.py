#!/usr/bin/env python
#
#
# Copyright (c) 2020, Arista Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
#   Neither the name of Arista Networks nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ARISTA NETWORKS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Description:
#
# Syntax:
# cvp_getarp -c --cvphost <cvphostname or ip-address>
#            -u --user <username>
#            -p --password <password> If omitted, password will be prompted.
#            -d <EOS device either hostname or ip address, or a list ','separated
#            -a <arp-ip-address> If omitted, the complete ARP table will be displayed of the device(s) from -d
#            =x Exclude a specific interface such as vxlan
#            -v verbose level=1,2, if level-identifier is omitted default=1
#
# Revision Level: 1.0 Date 29/5/2020
#                 1.1 Date 4/6/2020 Minor changes
#                 1.2 Date 2/9/20 Added -x to exclude an interface
#
# Note: For any question of comment: please email ralf-at-arista-dot-com with "cvp_getarp" in the subject.
#
#============
#
# Functions
#
def verbose_func(level,c_line):
    if level=="1":
        print("\nCVP_GETARP: %s" % (c_line))
    return
#
# Main code
#
import ssl
import json
import sys
import requests
import argparse
import getpass
import urllib3
#
# Init & Argument parsing
#
ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#
args = argparse.ArgumentParser()
args.add_argument(
    "-c",
    "--cvphost",
    dest="cvphost",
    action="store",
    required=True,
    help="CVP host name FQDN or IP",
)
args.add_argument(
    "-u",
    "--user",
    dest="user",
    action="store",
    required=True,
    help="CVP username",
)
args.add_argument(
    "-p",
    "--password",
    dest="passwd",
    action="store",
    required=False,
    default="",
    help="<cvpuser> password",
)
args.add_argument(
    "-d",
    "--device",
    dest="targetdev",
    action="store",
    required=True,
    help="Target Devices IP(s) or Device hostname(s), -d leaf1[,leaf2]",
)
args.add_argument(
    "-a",
    "--arp",
    dest="targetarp",
    action="store",
    required=False,
    default="ALL",
    help="ARP address to be checked",
)
args.add_argument(
    "-v",
    "--verbose",
    dest="verbose",
    action="store",
    required=False,
    choices=["0","1","2"],
    default="0",
    help="Verbose level 1 or 2",
)
#
args.add_argument(
    "-x",
    "--exclude",
    dest="exintf",
    action="store",
    required=False,
    help="Exclude an interface",
)
#
# Prepare the arguments
#
opts = args.parse_args()
host = opts.cvphost
user = opts.user
ExclIntf=opts.exintf
passwd = opts.passwd
targetdevs = opts.targetdev
targetarp="ALL"
targetarp = opts.targetarp
verbose= opts.verbose
#
# Check if passwd was provided
#
if passwd == "":
    passwd =  getpass.getpass(prompt='CVP Password: ', stream=None)
#
# Check targetip
#
targetlist=targetdevs.split(",")
#
# Prep CVP login
#
cvpIP = "https://"+host
#
headers = { 'Content-Type': 'application/json'}
#
# login API - you will need to login first
# and save the credentials in a cookie
loginURL = "/web/login/authenticate.do"
#
# send login request. If failed errormsg+sys.exit(-1)
#
try:
    response = requests.post(cvpIP+loginURL,json={'userId':user,'password':passwd},headers=headers,verify=False,timeout=5)
except:
    print("CVP_GETARP: HTTPS connection to CVP Host %s failed please check CVP host or IP address" % host)
    sys.exit(-1)
#
cookies = response.cookies
#
# Retrieve all provisioned EOS devices on CVP
# Create a list of dictionaries with: Serials, IP-address, Hostname 
#
url="/cvpservice/inventory/devices?provisioned=true"
try:
    response= requests.get(cvpIP+url,cookies=cookies, verify=False)
except:
    print("CVP_GETARP: CVP Inventory/devices failed status %s " % response)
    sys.exit(-1)
#
if response.status_code!=200:
    if response.status_code==401:
        print("CVP_GETARP: Status code %s from CVP Server %s please check your login credentials" % (response.status_code,host))
    else:
        print("CVP_GETARP: Status code %s from CVP Server %s to retrieve /cvpservice/inventory/devices" % (response.status_code,host))
    sys.exit(-1)
#
# Get the device list and match against the targetdevs
#
Mdevice_list=[]
Tdevice_list=[]
device_list=response.json()
verbose_func(verbose,device_list)
#
# search for target_device
#
for i in range(len(device_list)):
    device=device_list[i]
#
# Compare Device again target_device(s)
#
    for j in range(len(targetlist)):
        TFlag=False
        if device['hostname'].upper()==targetlist[j].upper():
            TFlag=True
        elif device['ipAddress']==targetlist[j]:
            TFlag=True
        if TFlag:
#
# Match found either IP or HOSTNAME
#
            verbose_func(verbose,"Match found "+targetlist[j])
            Mdevice_list.append(device['serialNumber'])
            Tdevice_list.append(targetlist[j])
#
# Device Dataset and associated tarlet list created
#
verbose_func(verbose,"Mdevice_list "+str(Mdevice_list))
verbose_func(verbose,"Tdevice_list"+str(Tdevice_list))
#
# Now have the serialnumbers why can use the this a SMASH dataset
#
restAPI = '/api/v1/rest/'
smash = "/Smash/arp/status/arpEntry"
#
ResultArp=[]
ResultMac=[]
ResultDev=[]
#
for i in range(len(Mdevice_list)):
    dataset=Mdevice_list[i]
    try:
        response = requests.get(cvpIP+restAPI+dataset+smash,cookies=cookies, verify=False)
    except:
        print("CVP_GETARP: ARP Entry retrival failed for %s connection to CVP Host %s " % (dataset,host))
        sys.exit(-1)
    if response.status_code!=200:
        print("CVP_GETARP: Status code %s from CVP Server %s to retrieve /Smash/arp/status/arpEntry" % (response.status_code,host))
        sys.exit(-1)
    verbose_func(verbose,"Device="+Tdevice_list[i]+" search")
    device_list=response.json()
#
# Start with list[1]
#
    arplist=device_list['notifications']
    arpdic=arplist[0]
    arplist=arpdic['updates']
    verbose_func(verbose,"arplist="+str(arplist))
    for arpitem in arplist.items():
#
# Search arplist dict
#
        verbose_func(verbose,"arpitem="+str(arpitem))
        for j in range(len(arpitem)):
            arp=arpitem[j]
            verbose_func(verbose,"arp="+str(arp))
            if type(arp)==dict:
                verbose_func(verbose,"arpkeys="+str(arp.keys()))
                keydic=arp['key']
                arpip=keydic['addr']
                valuedic=arp['value']
                arpmac=valuedic['ethAddr']
                arpintf=keydic['intfId']
                verbose_func(verbose,"Arp+mac+Interface="+arpip+" "+arpmac+" "+arpintf)
                xFlag=str(arpintf) not in str(ExclIntf)
                if xFlag and targetarp=="ALL":
                    ResultArp.append(arpip)
                    ResultMac.append(arpmac)
                    ResultDev.append(Tdevice_list[i])
                if xFlag and arpip==targetarp:
                    ResultArp.append(arpip)
                    ResultMac.append(arpmac)
                    ResultDev.append(Tdevice_list[i])
#
# Done
#
for i in range(len(ResultArp)):
    print("Arp=%s with Mac=%s found on device=%s" %(ResultArp[i],ResultMac[i],ResultDev[i]))
