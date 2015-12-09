#!/bin/bash

set -e

rm -rf out
mkdir out

while read h; do
    echo $h
    ./wildfire-to-stix.py --verbose -t wildfirecloud -f stix-il -h $h -o out/$h-il.xml > out/$h-il.log 2>&1
    ./wildfire-to-stix.py --verbose -t wildfirecloud -f stix-ol -h $h -o out/$h-ol.xml > out/$h-ol.log 2>&1
    ./wildfire-to-stix.py --verbose -t wildfirecloud --no-pcap --no-sample -f stix -h $h -o out/$h-stix.xml > out/$h-stix.log 2>&1
    ./wildfire-to-stix.py --verbose -t wildfirecloud --no-pcap --no-sample -f maec -h $h -o out/$h-maec.xml > out/$h-maec.log 2>&1
    ./wildfire-to-stix.py -e 0.0 --verbose -t wildfirecloud -f stix-il -h $h -o out/$h-il-e.xml > out/$h-il-e.log 2>&1
done < "$1"
