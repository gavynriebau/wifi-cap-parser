
# wifi-cap-parser

Tool for parsing / processing pcap files.

```bash
$ wifi-cap-parser
wifi-cap-parser 1.0
Gavyn Riebau <gavyn.riebau@gmail.com>
Utility functions to parsing wifi packet captures

USAGE:
    wifi-cap-parser [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    filter     Filters a 'wifiscan-export.csv' file (generated from Wifi Tracker android app) to only those networks
               whose password has been recovered and writes to /tmp/cracked.csv
    help       Prints this message or the help of the given subcommand(s)
    merge      Merges all .pcap files in the current directory and writes to /tmp/all.pcap
    potfile    Parses potfile and writes to "/tmp/creds.txt" lines with the format "<SSID>:<Password>"
```
