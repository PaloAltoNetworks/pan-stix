# pan-stix

A package to convert Palo Alto Networks threat information into STIX.

## Requirements

- python-maec (<https://github.com/MAECProject/python-maec>)
- python-cybox (<https://github.com/CybOXProject/python-cybox>)
- python-stix (<https://github.com/STIXProject/python-stix>)
- pan-python (<https://github.com/kevinsteves/pan-python>)
- lxml (from python-maec and python-cybox)

## wildfire-to-stix.py usage

- install required packages (see *Requirements*)
- configure .panrc with hostname and api of the Wildfire cloud (see <https://github.com/kevinsteves/pan-python/blob/master/doc/pan.xapi.rst> for details)
- run wildfire-to-stix.py to retrieve Wildfire reports and convert them to STIX format:

	wildfire-to-stix.py -t \<.panrc tag\> -h \<sample hash file\> -o \<stix package name\>

