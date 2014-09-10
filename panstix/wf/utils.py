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

class PanWfReportError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg

def set_malware_instance_object_attributes_from_wffileinfo(csubject, wffileinfo, wfreport):
    cmioa = cybox.core.Object()

    cmioa.properties = cybox.objects.file_object.File()
    cmioa.properties.file_name = "sample.exe"
    cmioa.properties.hashes = cybox.common.HashList()
    for cchild in wffileinfo:
        if cchild.tag == 'md5':
            cmioa.properties.hashes.append(cybox.common.Hash(cchild.text.strip(), type_="MD5"))
        elif cchild.tag == 'sha256':
            cmioa.properties.hashes.append(cybox.common.Hash(cchild.text.strip(), type_="SHA256"))
        elif cchild.tag == 'sha1':
            if cchild.text is not None:
                cmioa.properties.hashes.append(cybox.common.Hash(cchild.text.strip(), type_="SHA1"))
        elif cchild.tag == 'size':
            cmioa.properties.size_in_bytes = cchild.text.strip()
        elif cchild.tag == 'filetype':
            cmioa.properties.file_format = cchild.text.strip()
            # handle Android specific case
            if cmioa.properties.file_format == 'Android APK':
                fname = wfreport.xpath('//report/file_info/APK_Package_Name/text()')
                if len(fname) == 0:
                    logging.warning('no APK_Package_Name')
                    cmioa.properties.file_name = "sample"
                else:
                    fname = fname[0].strip()
                    cmioa.properties.file_name = fname
        else:
            logging.info('ignored file_info tag %s'%cchild.tag)

    csubject.set_malware_instance_object_attributes(cmioa)

def get_malware_subject_from_wfreport(wfreport, pcap=None):
    WFNS = cybox.utils.Namespace("http://wildfire.selfaddress.es/", "wildfire")
    maec.utils.set_id_namespace(WFNS)
    cybox.utils.set_id_namespace(WFNS)

    csubject = maec.package.malware_subject.MalwareSubject()

    # create malware instance object attribute from file_info structure
    wffileinfo = wfreport.xpath('file_info')
    if len(wffileinfo) != 1:
        raise PanWfReportError('wrong number of file_info objects in wildfire report: %d'%len(wffileinfo))

    wffileinfo = wffileinfo[0]
    set_malware_instance_object_attributes_from_wffileinfo(csubject, wffileinfo, wfreport)

    wfrreports = wfreport.xpath('task_info/report')
    if len(wfrreports) != 0:
        for cwfrr in wfrreports:
            rversion = cwfrr.xpath('version/text()')
            if len(rversion) != 1:
                logging.warning('wrong number of version objects in report: %d'%len(rversion))
                continue
            rversion = rversion[0].strip()
            logging.info('handling report %s'%rversion)
            if rversion == '0.1':
                report_0_1.add_malware_analysis_from_report(csubject, cwfrr, pcap)
            elif rversion == '2.0':
                report_2_0.add_malware_analysis_from_report(csubject, cwfrr, pcap)
            elif rversion == '3.0':
                report_3_0.add_malware_analysis_from_report(csubject, cwfrr, pcap)                
            else:
                logging.warning('unknown report version number: %s'%rversion)
                continue
    else:
        logging.warning('no report inside wildfire report')

    return csubject

def __get_wfpcap_funcgenerator(tag, hash, debug):
    import pan.wfapi

    def __get_wfpcap(platform=None):
        return pcap.get_raw_artifact_from_wfpcap_hash(tag, hash, debug, platform)

    return __get_wfpcap

def get_malware_subject_from_wfhash(tag, hash, add_pcap=True, debug=3):
    import pan.wfapi

    # retrieve wildfire report
    try:
        wfapi = pan.wfapi.PanWFapi(debug=debug,
                                   tag=tag)
    except pan.wfapi.PanWFapiError as msg:
        logging.error('pan.wfapi.PanWFapi:', msg)
        return None

    try:
        wfapi.report(hash=hash)
    except pan.wfapi.PanWFapiError as msg:
        logging.error('report: %s' % msg)
        return None

    if (wfapi.response_body is None):
        logging.error('no report from wildfire')
        return None

    if debug == 3:
        logging.debug(wfapi.response_body)

    wildfirereport = lxml.etree.fromstring(wfapi.response_body.encode('utf-8'))
    if wildfirereport.tag != 'wildfire':
        raise PanWfReportError('invalid root tag in wildfire report: %s'%wildfirereport.tag)

    if add_pcap is True:
        pcap = __get_wfpcap_funcgenerator(tag, hash, debug)
    else:
        pcap = None
    return get_malware_subject_from_wfreport(wildfirereport, pcap)


