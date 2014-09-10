### Requirements
- python-maec
- python-cybox
- python-stix
- pan-python with wfapi (wildfire branch)
- lxml (from python-maec and python-cybox)

#### lxml on Mac OS X
-	install libxml2 with brew:

		$ sudo brew install libxml2
		
- install lxml with pip:

		$ sudo pip install lxml

### Decisions
- there are several ways to express the input arguments of an action, I have chosen to specify them using **AssociatedObject** to be able to add a type to them. This way they can be easily processed and correlated to other CybOX objects. The alternative was to use ActionArguments, but they are not typed (Name (String) and Value (String))
- for reports with version 0.1 there is no clear process tree inside the report, i.e. there are multiple processes without a parent. To obtain a single process tree I have created a fake root process to be used as parent of all the orphaned processes.

### Issues
#### MAEC & STIX
- seems there is no way to specify inside MAEC the original file contents
- the Process_Tree structure under Bundle is too limited. What if a malware is writing in a different process memory ?
- there is no way to specify interesting attributes for IP address (country, AS, ...)
- no support for APK files

#### Implementation
- what should I use for our namespace (ids, ...)
- in Malware Instance Object Attributes, under file format I am reporting the "filetype" content from file_info structure. Is it correct ? Should I use a different string ?

#### Wildfire reports
For report 0.1:
- no timestamp for actions in WF report...
- no timeline
- in **process_terminated** who is the process that performed the action ?
For report 2.0/3.0:
- timeline difficult to parse
- in SetKey, subkey is the value name, right ?
- in Create process, child_pid=0 means injection ?
- timeline impossible to reconstruct (no pid, no timestamp)
- no timestamp
- network activity not bound the processes

#### Development process
- python-maec is buggy:
	- in package_generator_example.py properties.name should be properties.file_name
- modified pan-python wfapi to support multi-platforms in pcap retrieval

### TODO
- in report 0.1, cleanup the code to reconstruct the process tree
- use exception instead of messages on stderr !
- strip values from xml before comparing
- parse the timeline
- parse APK analysis
- restructure code to specialize report parser, i.e. parser for 3.0 is the parser 2.0 with just some code added