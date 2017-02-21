# targetedthreats

Collection of IOCs related to targeting of civil society.
If you're interested, I also compile a list of [Reports](https://github.com/botherder/targetedthreats/wiki/Reports) detailing attacks
against activists, dissidents and journalists.

You will find a *targeted.csv* file containing the list of indicators,
a *disabled.csv* which contains incomplete indicators, and *targetedthreats.rules*
which contains usable Snort rules generated from the indicators list.

The utility *snortify.py* is used to generate the Snort rules.

The utility *extract.py* is just simply to easily extract list of IPs and/or domains:

    usage: extract.py [-h] [--all] [--ip] [--domains] ioc_path

    Targeted Threats IOC Extractor

    positional arguments:
      ioc_path

    optional arguments:
      -h, --help     show this help message and exit
      --all, -a      Get all indicators
      --ip, -i       Get only IP addresses
      --domains, -d  Get only domains

## Licensing

The source code in this repository is licensed under GPL v3 and
copyrighted by Claudio Guarnieri.

The list of indicators is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
