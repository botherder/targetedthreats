#!/usr/bin/env

import os
import csv
import sys
import socket

def is_ip(ioc):
    try:
        socket.inet_aton(ioc)
    except socket.error:
        return False
    else:
        return True

def generate_rule(ioc, family=None, country=None, reference=None, counter=1):
    message_suffix = ""
    if family:
        message_suffix += " related to {}".format(family)
    if country:
        message_suffix += " (seen in {})".format(country)

    sid = 9100000 + counter

    if is_ip(ioc):
        message = "Traffic to suspicious IP" + message_suffix

        alert = "alert ip any any -> {} any (msg:\"{}\"; reference:url,{}; classtype:trojan-activity; sid:{}; rev:0;)".format(
            ioc, message, reference, sid)
    else:
        message = "Suspicious DNS request" + message_suffix

        domain_pattern = ''
        for part in ioc.split('.'):
            domain_pattern += '|{:02X}|{}'.format(len(part), part)

        alert = "alert udp any any -> any 53 (msg:\"{}\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth: 10; offset: 2; content:\"{}\"; nocase; distance: 0; fast_pattern; reference:url,{}; sid:{}; rev:0;)".format(
            message, domain_pattern, reference, sid)

    return alert

def main(ioc_path):
    if not os.path.exists(ioc_path):
        print("[!] ERROR: IOC file does not exist at path {}".format(ioc_path))
        return

    with open(ioc_path, 'r') as handle:
        reader = csv.reader(handle)
        counter = 1
        for row in reader:
            print generate_rule(row[0], row[1], row[2], row[3], counter)
            counter += 1

if __name__ == '__main__':
    main(sys.argv[1])
