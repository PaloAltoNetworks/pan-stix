#!/usr/bin/env python

#
# Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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

from __future__ import print_function

import sys
import argparse
import logging

from panstix import __version__
import panstix.utils
import panstix.packaging

LOG = logging.getLogger(__name__)


def dump_report_to_stix(options):
    panstix.utils.set_id_namespace(
        "https://github.com/PaloAltoNetworks-BD/pan-stix",
        "pan-stix"
    )

    sp = panstix.packaging.get_stix_package_from_wfreport(
        hash=options.hash,
        tag=options.tag,
        report=options.inreport,
        sample=options.sample,
        pcap=options.pcap
    )
    if options.outfile is not None:
        f = open(options.outfile, 'w')
        f.write(sp.to_xml())
        f.close()
    else:
        sys.stdout.write(sp.to_xml())


def dump_report_to_stix_ol(options):
    panstix.utils.set_id_namespace(
        "https://github.com/PaloAltoNetworks-BD/pan-stix",
        "pan-stix"
    )

    sp = panstix.packaging.get_stix_ol_package_from_wfreport(
        hash=options.hash,
        tag=options.tag,
        report=options.inreport
    )

    if options.outfile is not None:
        f = open(options.outfile, 'w')
        f.write(sp.to_xml())
        f.close()
    else:
        sys.stdout.write(sp.to_xml())


def dump_report_to_stix_il(options):
    panstix.utils.set_id_namespace(
        "https://github.com/PaloAltoNetworks-BD/pan-stix",
        "pan-stix"
    )

    sp = panstix.packaging.get_stix_il_package_from_wfreport(
        hash=options.hash,
        tag=options.tag,
        report=options.inreport,
        evidence=options.evidence
    )

    if options.outfile is not None:
        f = open(options.outfile, 'w')
        f.write(sp.to_xml())
        f.close()
    else:
        sys.stdout.write(sp.to_xml())


def dump_report_to_maec(options):
    panstix.utils.set_id_namespace(
        "https://github.com/PaloAltoNetworks-BD/pan-stix",
        "pan-stix"
    )

    mp = panstix.packaging.get_maec_package_from_wfreport(
        hash=options.hash,
        report=options.inreport,
        tag=options.tag,
        pcap=options.pcap
    )

    if options.outfile is not None:
        f = open(options.outfile, 'w')
        f.write(mp.to_xml())
        f.close()
    else:
        sys.stdout.write(mp.to_xml())


def _parse_opts():
    parser = argparse.ArgumentParser(
        description="Convert Palo Alto Networks Wildfire reports to STIX/MAEC",
        add_help=False
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        '-t', '--tag',
        metavar='<pan-python tag>',
        action='store',
        help='pan-python tag for Wildfire API'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='verbose'
    )
    parser.add_argument(
        '-h', '--hash',
        action='store',
        metavar='<hash>',
        help='hash of the sample'
    )
    parser.add_argument(
        '--help',
        action='help',
        help='help'
    )
    parser.add_argument(
        '-i', '--in',
        dest='inreport',
        metavar='<report filename>',
        action='store',
        help='local Wildfire report'
    )
    parser.add_argument(
        '--no-pcap',
        dest='no_pcap',
        action='store_true',
        default=False,
        help='do not include pcap'
    )
    parser.add_argument(
        '--pcap',
        dest='pcap',
        metavar='<pcap source>',
        action='store',
        default='network',
        help='pcap filename or \'network\' for retriving from Wildfire API'
    )
    parser.add_argument(
        '--no-sample',
        dest='no_sample',
        action='store_true',
        default=False,
        help='do not include sample'
    )
    parser.add_argument(
        '--sample',
        dest='sample',
        action='store',
        default='network',
        metavar='<sample source>',
        help='sample filename or \'network\' for retriving from Wildfire API'
    )
    parser.add_argument(
        '-f', '--outfmt',
        action='store',
        metavar='<output format>',
        default='stix',
        choices=['stix', 'stix-il', 'stix-ol', 'maec'],
        help='output format'
    )
    parser.add_argument(
        '-o', '--out',
        action='store',
        dest='outfile',
        metavar='<output filename>',
        help='output filename'
    )
    parser.add_argument(
        '-e', '--evidence',
        action='store',
        dest='evidence',
        type=float,
        metavar='<evidence score>',
        help='minimum evidence score'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.no_pcap:
        options.pcap = None
    if options.no_sample:
        options.sample = None

    if options.hash is not None and options.inreport is not None:
        print('CRITICAL: only one of \'in\' or \'hash\' should be specified',
              file=sys.stderr)
        sys.exit(1)

    if options.hash is None and options.inreport is None:
        print('CRITICAL: one of \'in\' or \'hash\' should be specified',
              file=sys.stderr)
        sys.exit(1)

    if options.hash is not None and options.tag is None:
        print('CRITICAL: tag should be specified to retrieve reports by hash',
              file=sys.stderr)
        sys.exit(1)

    if options.pcap == 'network' and options.tag is None:
        print('CRITICAL: tag should be specified to retrieve pcaps',
              file=sys.stderr)
        sys.exit(1)

    if options.sample == 'network' and options.tag is None:
        print('CRITICAL: should be specified to retrieve samples',
              file=sys.stderr)
        sys.exit(1)

    return options


def main():
    options = _parse_opts()

    loglevel = logging.INFO
    if options.verbose:
        loglevel = logging.DEBUG

    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%d/%m/%Y %I:%M:%S %p',
        level=loglevel
    )

    if options.outfmt == 'stix':
        dump_report_to_stix(options)
    elif options.outfmt == 'maec':
        dump_report_to_maec(options)
    elif options.outfmt == 'stix-ol':
        dump_report_to_stix_ol(options)
    elif options.outfmt == 'stix-il':
        dump_report_to_stix_il(options)
    else:
        logging.critical('unhandled output format %s' % options.outfmt)
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
