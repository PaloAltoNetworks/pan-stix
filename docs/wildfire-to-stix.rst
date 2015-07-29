wildfire-to-stix
================

Usage
-----

::

    usage: wildfire-to-stix.py [--version] [-t <pan-python tag>] [--verbose]
                               [-h <hash>] [--help] [-i <report filename>]
                               [--no-pcap] [--pcap <pcap source>] [--no-sample]
                               [--sample <sample source>] [-f <output format>]
                               [-o <output filename>]
    
    Convert Palo Alto Networks Wildfire reports to STIX/MAEC
    
    optional arguments:
      --version             show program's version number and exit
      -t <pan-python tag>, --tag <pan-python tag>
                            pan-python tag for Wildfire API
      --verbose             verbose
      -h <hash>, --hash <hash>
                            hash of the sample
      --help                help
      -i <report filename>, --in <report filename>
                            local Wildfire report
      --no-pcap             do not include pcap
      --pcap <pcap source>  pcap filename or 'network' for retriving from Wildfire
                            API
      --no-sample           do not include sample
      --sample <sample source>
                            sample filename or 'network' for retriving from
                            Wildfire API
      -f <output format>, --outfmt <output format>
                            output format
      -o <output filename>, --out <output filename>
                            output filename
