#
# Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import sys
import getopt
import logging

import datetime
import dateutil.tz

import panstix.utils
import panstix.packaging

def dump_report_to_stix(options):
    panstix.utils.set_id_namespace("https://github.com/PaloAltoNetworks-BD/pan-stix", "pan-stix")

    subargs = {k: v for k,v in options.iteritems() if k in ['hash', 'debug', 'tag', 'sample', 'pcap']}
    if 'inreport' in options:
        subargs['report'] = options['inreport']

    sp = panstix.packaging.get_stix_package_from_wfreport(**options)
    if options['outfile'] is not None:
        f = open(options['outfile'], 'w')
        f.write(sp.to_xml())
        f.close()
    else:
        sys.stdout.write(sp.to_xml())

def dump_report_to_maec(options):
    panstix.utils.set_id_namespace("https://github.com/PaloAltoNetworks-BD/pan-stix", "pan-stix")

    subargs = {k: v for k,v in options.iteritems() if k in ['hash', 'debug', 'tag', 'sample', 'pcap']}
    if 'inreport' in options:
        subargs['report'] = options['inreport']

    mp = panstix.packaging.get_maec_package_from_wfreport(**options)
    if options['outfile'] is not None:
        f = open(options['outfile'], 'w')
        f.write(mp.to_xml())
        f.close()
    else:
        sys.stdout.write(mpp.to_xml())

def parse_opts():
    options = {
        'tag': None,
        'debug': 0,
        'hash': None,
        'pcap': 'network',
        'sample': 'network',
        'inreport': None,
        'outfmt': 'stix',
        'outfile': None
    }

    valid_outfmt = ['stix', 'maec']
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
    elif options['outfmt'] == 'maec':
        dump_report_to_maec(options)
    else:
        logging.critical('unhandled output format %s'%options['outfmt'])
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()