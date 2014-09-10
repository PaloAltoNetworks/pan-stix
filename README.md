### Requirements
- python-maec
- python-cybox
- python-stix
- pan-python with wfapi (wildfire branch)
- lxml (from python-maec and python-cybox)

### Usage

.panrc should contains hostname and api of the wildfire server to be used.

	wildfire-to-stix.py -t <.panrc tag> -h <sample hash file> -o <stix package name>

#### lxml on Mac OS X
-	install libxml2 with brew:

		$ sudo brew install libxml2
		
- install lxml with pip:

		$ sudo pip install lxml
		
