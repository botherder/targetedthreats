#!/usr/bin/env python
# Copyright (c) 2017, Claudio "nex" Guarnieri
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

from utils import is_ip

def get_iocs():
    iocs = []
    with open("targetedthreats.csv", "r") as handle:
        reader = csv.reader(handle)
        for row in reader:
            ioc = row[0]
            if ioc.startswith("#"):
                continue

            iocs.append(ioc)                

    return iocs

def is_good(ioc):
    blacklist = [
        ".static.",
        ".dynamic.",
        ".rnds.",
        ".amazonaws.com"
    ]

    for nope in blacklist:
        if nope in ioc:
            return False

    return True

def main(ioc_path):
    if not os.path.exists(ioc_path):
        print("[!] The IOC file at path " + ioc_path + " does not exist.")
        return

    iocs = get_iocs()

    family = raw_input(">>> Provide the family name: ")
    country = raw_input(">>> Provide the country: ")
    reference = raw_input(">>> Provide URL to report: ")

    collection = open("targetedthreats.csv", "a")
    writer = csv.writer(collection, quoting=csv.QUOTE_ALL)

    with open(ioc_path, "r") as handle:
        for line in handle:
            ioc = line.strip()
            if not ioc:
                continue

            if not is_good(ioc):
                print("[!] Skipped IOC because of blacklist: " + ioc)
                continue

            if ioc not in iocs:
                print("[+] Adding new row to collection for IOC: " + ioc)
                new_row = [ioc, family, country, reference]
                writer.writerow(new_row)
            else:
                print("[-] Skipped IOC because already existing: " + ioc)

    collection.close()

if __name__ == '__main__':
    main(sys.argv[1])
