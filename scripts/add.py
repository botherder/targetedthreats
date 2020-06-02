#!/usr/bin/env python3
# Copyright (c) 2017-2018, Claudio "nex" Guarnieri
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
import socket
from argparse import ArgumentParser

def is_ip(ioc):
    try:
        socket.inet_aton(ioc)
    except socket.error:
        return False
    else:
        return True

def get_iocs(csv_path):
    iocs = []
    with open(csv_path, 'r') as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            iocs.append(row['ioc'])

    return iocs

def is_good(ioc):
    blocklist = [
        ".static.",
        ".dynamic.",
        ".rnds.",
        ".amazonaws.com"
    ]

    for nope in blocklist:
        if nope in ioc:
            return False

    return True

def clean_indicator(ioc):
    ioc = ioc.lower()
    ioc = ioc.strip()
    ioc = ioc.replace('[.]', '.')
    return ioc

def main():
    parser = ArgumentParser(description="Add new indicators to the CSV list")
    parser.add_argument('ioc_path', action="store")
    parser.add_argument('csv_path', action="store")
    args, unknown = parser.parse_known_args()

    if not os.path.exists(args.ioc_path) or not os.path.exists(args.csv_path):
        parser.print_usage()
        print("ERROR: You need to provide valid ioc_path and csv_path")
        sys.exit(-1)

    iocs = get_iocs(args.csv_path)

    family = input(">>> Provide the family name: ")
    country = input(">>> Provide the country: ")
    reference = input(">>> Provide URL to report: ")

    collection = open(args.csv_path, 'a')
    writer = csv.writer(collection, quoting=csv.QUOTE_ALL)

    with open(args.ioc_path, 'r') as handle:
        for line in handle:
            ioc = clean_indicator(line)
            if ioc == '':
                continue

            if not is_good(ioc):
                print("[!] Skipped IOC because of blocklist: " + ioc)
                continue

            if ioc not in iocs:
                print("[+] Adding new row to collection for IOC: " + ioc)
                ioc_type = 'domain'
                if is_ip(ioc):
                    ioc_type = 'ip_address'
                new_row = [ioc_type, ioc, family, country, reference]
                writer.writerow(new_row)
            else:
                print("[-] Skipped IOC because already existing: " + ioc)

    collection.close()

if __name__ == '__main__':
    main()
