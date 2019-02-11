#!/usr/bin/env python3
# Copyright (c) 2019, Claudio "nex" Guarnieri
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

import json
from argparse import ArgumentParser

def main():
    parser = ArgumentParser(description="Extract statistics from JSON list")
    parser.add_argument('input', action="store")

    args, unknown = parser.parse_known_args()

    reports = {}
    with open(args.input, 'r') as handle:
        for line in handle:
            data = json.loads(line)

            if data['reference'] not in reports:
                reports[data['reference']] = [data['country'],]
            else:
                if data['country'] not in reports[data['reference']]:
                    reports[data['reference']].append(data['country'])

    country_count = {}
    for key, value in reports.items():
        for country in value:
            if country not in country_count:
                country_count[country] = 1
            else:
                country_count[country] += 1

    country_sorted = sorted(country_count.items(), key=lambda k: k[1], reverse=True)

    print("Number of reports per country:")
    for country in country_sorted:
        print(country[1], country[0])

if __name__ == '__main__':
    main()
