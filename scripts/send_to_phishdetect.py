#!/usr/bin/env python3
# Copyright (c) 2020, Claudio "nex" Guarnieri
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
from phishdetect import PhishDetect

def clean_tag(tag):
    tag = tag.lower().replace(" ", "_").strip()
    if tag == "misc":
        return ""
    else:
        return tag

def main():
    parser = ArgumentParser(description="Send domains to a PhishDetect Node")
    parser.add_argument("--host", "-H", required=True, help="Address of your preferred PhishDetect Node")
    parser.add_argument("--api-key", "-k", required=True, help="Your API key")
    parser.add_argument("csv_path", help="The targetedthreats.csv file containing the list of indicators")
    args = parser.parse_args()

    if not os.path.exists(args.csv_path):
        print(f"ERROR: The file does not exist at path {args.csv_path}")
        sys.exit(-1)

    pd = PhishDetect(host=args.host, api_key=args.api_key)

    with open(args.csv_path, "r") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not "type" in row or row["type"] != "domain":
                continue

            ioc = row["ioc"]
            tags = ["targetedthreats",]
            for tag in [row["family"], row["country"]]:
                tag = clean_tag(tag)
                if tag != "":
                    tags.append(tag)

            print(f"Submitting indicator {ioc} with tags {tags}")
            result = pd.indicators.add(indicators=[ioc,], tags=tags)
            if "error" in result:
                print(f"ERROR: Submitting of indicators failed: {result['error']}")
            else:
                print(result["msg"])

if __name__ == "__main__":
    main()
