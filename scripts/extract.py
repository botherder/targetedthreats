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
from argparse import ArgumentParser

def main():
    parser = ArgumentParser(description="Targeted Threats IOC Extractor")
    parser.add_argument("--all", "-a", action="store_true", help="Get all indicators")
    parser.add_argument("--ip", "-i", action="store_true", help="Get only IP addresses")
    parser.add_argument("--domains", "-d", action="store_true", help="Get only domains")
    parser.add_argument("csv_path", action="store")

    args, unknown = parser.parse_known_args()

    if not args.all and not args.ip and not args.domains:
        parser.print_usage()
        sys.exit(-1)

    if not os.path.exists(args.csv_path):
        print("[!] ERROR: IOC file does not exist at path {}".format(args.csv_path))
        return

    with open(args.csv_path, "r") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if (args.all or args.ip) and row["type"] == "ip_address":
                print(row["ioc"])
            elif (args.all or args.domains) and row["type"] == "domain":
                print(row["ioc"])

if __name__ == "__main__":
    main()
