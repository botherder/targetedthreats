#!/usr/bin/env python3
# Copyright (c) 2016-2018, Claudio "nex" Guarnieri
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# * Neither the name of the {organization} nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import csv
import sys
from argparse import ArgumentParser

def generate_rule(row, counter=1):
    message_suffix = ""
    if row['family']:
        message_suffix += " - related to {}".format(row['family'])
    if row['country']:
        message_suffix += " (seen in {})".format(row['country'])

    sid = 9100000 + counter

    if row['type'] == 'ip_address':
        message = "Traffic to suspicious IP {}{}".format(row['ioc'], message_suffix)

        alert = "alert ip any any -> {} any (msg:\"{}\"; reference:url,{}; classtype:trojan-activity; sid:{}; rev:0;)".format(
            row['ioc'], message, row['reference'], sid)
    else:
        message = "Suspicious DNS request {}{}".format(row['ioc'], message_suffix)

        domain_pattern = ''
        for part in row['ioc'].split('.'):
            domain_pattern += '|{:02X}|{}'.format(len(part), part)

        alert = "alert udp any any -> any 53 (msg:\"{}\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth: 10; offset: 2; content:\"{}\"; nocase; distance: 0; fast_pattern; reference:url,{}; classtype:trojan-activity; sid:{}; rev:0;)".format(
            message, domain_pattern, row['reference'], sid)

    return alert

def main(csv_path):
    parser = ArgumentParser(description="Targeted Threats IOC Extractor")
    parser.add_argument('csv_path', action="store")
    args, unknown = parser.parse_known_args()

    if not os.path.exists(args.csv_path):
        print("[!] ERROR: IOC file does not exist at path {}".format(args.csv_path))
        return

    with open(args.csv_path, 'r') as handle:
        reader = csv.DictReader(handle)
        counter = 1
        for row in reader:
            try:
                print(generate_rule(row, counter))
            except IndexError:
                continue

            counter += 1

if __name__ == '__main__':
    main(sys.argv[1])
