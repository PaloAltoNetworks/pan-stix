### Requirements
- python-maec
- python-cybox
- python-stix
- pan-python with wfapi (wildfire branch)
- lxml (from python-maec and python-cybox)

### Simple usage

	wildfire-to-stix.py -h <sample hash file> -o <stix package name>

#### lxml on Mac OS X
-	install libxml2 with brew:

		$ sudo brew install libxml2
		
- install lxml with pip:

		$ sudo pip install lxml
		
