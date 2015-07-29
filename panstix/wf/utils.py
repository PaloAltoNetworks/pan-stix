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

import logging

import lxml

import cybox.core
import cybox.common
import cybox.objects.file_object

import maec.package.malware_subject

import cybox.utils
import maec.utils

from . import report_0_1
from . import report_2_0
from . import report_3_0
from . import pcap

LOG = logging.getLogger(__name__)


class PanWfReportError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg


def get_malware_instance_object_attributes_from_fileinfo(wffileinfo, wfreport):
    cmioa = cybox.core.Object()

    cmioa.properties = cybox.objects.file_object.File()
    cmioa.properties.file_name = "sample.exe"
    cmioa.properties.hashes = cybox.common.HashList()
    for cchild in wffileinfo:
        if cchild.tag == 'md5':
            cmioa.properties.hashes.append(
                cybox.common.Hash(cchild.text.strip(), type_="MD5")
            )
        elif cchild.tag == 'sha256':
            cmioa.properties.hashes.append(
                cybox.common.Hash(cchild.text.strip(), type_="SHA256")
            )
        elif cchild.tag == 'sha1':
            if cchild.text is not None:
                cmioa.properties.hashes.append(
                    cybox.common.Hash(cchild.text.strip(), type_="SHA1")
                )
        elif cchild.tag == 'size':
            cmioa.properties.size_in_bytes = cchild.text.strip()
        elif cchild.tag == 'filetype':
            cmioa.properties.file_format = cchild.text.strip()
            # handle Android specific case
            if cmioa.properties.file_format == 'Android APK':
                fname = wfreport.xpath(
                    '//report/file_info/APK_Package_Name/text()'
                )
                if len(fname) == 0:
                    LOG.warning('no APK_Package_Name')
                    cmioa.properties.file_name = "sample"
                else:
                    fname = fname[0].strip()
                    cmioa.properties.file_name = fname
        else:
            LOG.info('ignored file_info tag %s' % cchild.tag)

    return cmioa


def add_malware_analysis_from_report(csubject, wfrreport, pcapcb):
    wfrreports = wfrreport.xpath('task_info/report')
    if len(wfrreports) != 0:
        for cwfrr in wfrreports:
            rversion = cwfrr.xpath('version/text()')
            if len(rversion) != 1:
                LOG.warning('wrong number of version objects in report: %d' %
                            len(rversion))
                continue
            rversion = rversion[0].strip()
            LOG.info('handling report %s' % rversion)
            if rversion == '0.1':
                report_0_1.add_malware_analysis_from_report(
                    csubject,
                    cwfrr,
                    pcapcb
                )
            elif rversion == '2.0':
                report_2_0.add_malware_analysis_from_report(
                    csubject,
                    cwfrr,
                    pcapcb
                )
            elif rversion == '3.0':
                report_3_0.add_malware_analysis_from_report(
                    csubject,
                    cwfrr,
                    pcapcb
                )
            else:
                LOG.warning('unknown report version number: %s' % rversion)
                continue
    else:
        LOG.warning('no report inside wildfire report')


def __create_malware_subject_from_report(wfreport, pcap=None):
    WFNS = cybox.utils.Namespace(
        "https://github.com/PaloAltoNetworks-BD/pan-stix",
        "pan-stix"
    )
    maec.utils.set_id_namespace(WFNS)
    cybox.utils.set_id_namespace(WFNS)

    csubject = maec.package.malware_subject.MalwareSubject()

    # create malware instance object attribute from file_info structure
    wffileinfo = wfreport.xpath('file_info')
    if len(wffileinfo) != 1:
        raise PanWfReportError(
            'wrong number of file_info objects in wildfire report: %d' %
            len(wffileinfo)
        )

    wffileinfo = wffileinfo[0]
    cmioa = get_malware_instance_object_attributes_from_fileinfo(
        wffileinfo,
        wfreport
    )
    csubject.set_malware_instance_object_attributes(cmioa)

    add_malware_analysis_from_report(csubject, wfreport, pcap)

    return csubject


def __get_wfpcap_network_funcgenerator(tag, hash):
    def __get_wfpcap(platform=None):
        return pcap.get_raw_artifact_from_pcap_hash(tag, hash, platform)

    return __get_wfpcap


def __get_wfpcap_file_funcgenerator(fnametemplate, hash):
    def __get_wffile(platform=None):
        try:
            p = (platform if platform is not None else 'np')
            f = open(
                fnametemplate % {'hash': hash, 'platform': p},
                'rb'
            )
            pc = f.read()
            f.close()
        except:
            LOG.exception('Error in opening pcap file')
            return None

        return pcap.get_raw_artifact_from_pcap(pc)

    return __get_wffile


def get_malware_subject_from_report(**kwargs):
    hash = kwargs.get('hash', None)

    if 'report' in kwargs:
        if hasattr(kwargs['report'], 'read'):
            report = lxml.etree.parse(kwargs['report']).getroot()
        else:
            f = open(kwargs['report'], 'rb')
            report = lxml.etree.parse(f).getroot()
            f.close()
        if hash is None:
            hash = report.xpath('file_info/sha256/text()')
            if len(hash) != 0:
                hash = hash[0].strip()
            else:
                hash = None
    elif 'hash' in kwargs and \
         'tag' in kwargs:
        import pan.wfapi

        # retrieve wildfire report
        wfapi = pan.wfapi.PanWFapi(tag=kwargs['tag'])
        wfapi.report(hash=kwargs['hash'])
        if (wfapi.response_body is None):
            raise PanWfReportError('no report from wildfire')

        report = lxml.etree.fromstring(wfapi.response_body.encode('utf-8'))
    else:
        raise PanWfReportError(
            'wrong set of arguments to get_malware_subject_from_report'
        )

    if report.tag != 'wildfire':
        raise PanWfReportError('invalid root tag in wildfire report: %s' %
                               report.tag)

    if 'pcap' in kwargs:
        p = kwargs['pcap']
        if p == 'network':
            if 'tag' not in kwargs:
                raise PanWfReportError('pcap from network, '
                                       'but no tag specified')
            pcap = __get_wfpcap_network_funcgenerator(kwargs['tag'], hash)
        elif isinstance(p, basestring):
            pcap = __get_wfpcap_file_funcgenerator(p, hash)
        else:
            pcap = None
    else:
        pcap = None

    return __create_malware_subject_from_report(report, pcap)
