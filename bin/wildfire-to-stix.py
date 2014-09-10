# XXX pcap when report is retrieved from file

import sys
import getopt
import logging

import datetime
import dateutil.tz

# lxml
import lxml

import stix.core
import stix.indicator
import stix.ttp
import stix.ttp.behavior
import stix.utils
import cybox.utils
import cybox.core
import stix.extensions.malware.maec_4_1_malware
import maec.package.malware_subject

import panstix.wf
import panstix.wf.sample
import panstix.utils

def dump_report_to_stix(options):
    panstix.utils.set_id_namespace("http://wildfire.selfaddress.es/": "wildfire")

    if options['inreport'] is not None:
        f = open(options['inreport'], 'rb')
        twfreport = f.read()
        f.close()
        wildfirereport = lxml.etree.fromstring(twfreport)
        if wildfirereport.tag != 'wildfire':
            logging.critical('invalid root tag in wildfire report: %s'%wildfirereport.tag, file=sys.stderr)
            sys.exit(1)
        ms = panstix.wf.get_malware_subject_from_wfreport(wildfirereport)
    elif options['hash'] is not None:
        ms = panstix.wf.get_malware_subject_from_wfhash(options['tag'], options['hash'], options['pcap'], options['debug'])

    msl = maec.package.malware_subject.MalwareSubjectList()
    msl.append(ms)

    msletree = lxml.etree.fromstring(msl.to_xml(pretty=False)) # XXX ugly !!!! 

    mi = stix.extensions.malware.maec_4_1_malware.MAECInstance(msletree)
    ttp = stix.ttp.TTP()
    mb = stix.ttp.behavior.Behavior()
    mb.add_malware_instance(mi)
    ttp.behavior = mb

    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader()
    stix_header.description = "Malware "+(options['hash'] if options['hash'] is not None else 'sample')+" Artifacts and Characterization"
    stix_package.stix_header = stix_header
    stix_package.add_ttp(ttp)

    if options['hash'] is not None and options['sample']:
        i = stix.indicator.Indicator(title="Wildfire sample "+options['hash'])
        o = cybox.core.Observable()
        o.description = "Raw artifact object of wildfire sample "+options['hash']
        rao = panstix.wf.sample.get_raw_artifact_from_wfsample_hash(options['tag'], options['hash'], options['debug'])
        if rao is not None:
            o.object_ = rao
            i.add_observable(o)
            i.add_indicated_ttp(stix.ttp.TTP(idref=ttp.id_))
            stix_package.add_indicator(i)

    if options['outfile'] is not None:
        f = open(options['outfile'], 'w')
        f.write(stix_package.to_xml())
        f.close()
    else:
        sys.stdout.write(stix_package.to_xml())

def parse_opts():
    options = {
        'tag': None,
        'debug': 0,
        'hash': None,
        'pcap': True,
        'sample': True,
        'inreport': None,
        'outfmt': 'stix',
        'outfile': None
    }

    valid_outfmt = ['stix']
    short_options = 't:Dh:i:o:f:'
    long_options = ['no-pcap', 'no-sample']

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                short_options, long_options)
    except getopt.GetoptError as error:
        logging.critical(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-t':
            if arg:
                options['tag'] = arg
        elif opt == '-D':
            if not options['debug'] < 3:
                logging.critical('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
            options['debug'] += 1
        elif opt == '-h':
            if options['inreport'] is not None:
                logging.critical('only one of inreport or hash should be specified', file=sys.stderr)
                sys.exit(1)
            options['hash'] = arg
        elif opt == '--no-pcap':
            options['pcap'] = False
        elif opt == '--no-sample':
            options['sample'] = False
        elif opt == '-i':
            if options['hash'] is not None:
                logging.critical('only one of inreport or hash should be specified', file=sys.stderr)
                sys.exit(1)                
            options['inreport'] = arg
        elif opt == '-f':
            if not arg in valid_outfmt:
                logging.critical('invalid output format', file=sys.stderr)
                sys.exit(1)
            options['outfmt'] = arg
        elif opt == '-o':
            options['outfile'] = arg
        else:
            logging.critical('unhandled option %s'%opt)
            sys.exit(1)

    if options['inreport'] is None and options['hash'] is None:
        logging.critical('at least one of hash or inreport should be specified')
        sys.exit(1)

    if options['hash'] is not None and options['tag'] is None:
        logging.critical('tag should be specified to retrieve reports by hash')
        sys.exit(1)

    if options['pcap'] and options['tag'] is None:
        logging.critical('tag should be specified to retrieve pcaps')
        sys.exit(1)

    if options['sample'] and options['tag'] is None:
        logging.critical('tag should be specified to retrieve samples')
        sys.exit(1)

    return options

def main():
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p', level=logging.DEBUG)

    options = parse_opts()

    if options['outfmt'] == 'stix':
        dump_report_to_stix(options)
    else:
        logging.critical('unhandled output format %s'%options['outfmt'])
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
