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

import subprocess
import optparse
import re


# Future improvements
# Select random MAC from specified vendor, Generate random MAC, Autorun at startup with specified MAC

def get_cmd_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change (defaults to 'wlan0'")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address (defaults to '00:11:22:33:44:55'")
    (options, arguements) = parser.parse_args()

    if not options.interface:
        options.interface = "wlan0"

    if not options.new_mac:
        options.new_mac = "00:11:22:33:44:55"
    else:
        options.new_mac = str(options.new_mac.lower())
        if not re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", options.new_mac):
            parser.error("Please enter a valid MAC address in the form 0A:1B:2C:3D:4E:5F")

    return options


def change_mac(interface, new_mac):
    print("[+] Changing MAC of interface " + interface + ", currently " + old_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_regex_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

    return mac_address_regex_search_result.group(0)


options = get_cmd_args()
old_mac = get_current_mac(options.interface)
change_mac(options.interface, options.new_mac)

if get_current_mac(options.interface) == options.new_mac:
    print("[=] Success! MAC of interface " + options.interface + " changed to " + get_current_mac(options.interface))
else:
    print("[-] Error, use --help for usage info")
