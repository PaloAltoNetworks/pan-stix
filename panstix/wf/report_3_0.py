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

import time
import datetime
import logging

# lxml
import lxml

# STIX, MAEC and CybOX imports
import maec.package.package
import maec.package.malware_subject
import maec.package.analysis
import maec.bundle.bundle
import maec.bundle.malware_action
import maec.bundle.process_tree
import maec.bundle.behavior
import cybox.core
import cybox.common
import cybox.objects.file_object
import cybox.objects.process_object
import cybox.utils
import maec.utils

from . import maecactions

def __analyze_process_tree(pdict, plist, parent):
    for p in plist:
        pid = p.get('pid')
        cpn = maec.bundle.process_tree.ProcessTreeNode()
        cpn.pid = pid
        cpn.name = p.get('name')
        cpn.image_info = cybox.objects.process_object.ImageInfo()
        cpn.image_info.file_name = p.get('text')
        parent.add_spawned_process(cpn)
        pdict[pid] = cpn
        for c in p:
            if c.tag == 'child':
                __analyze_process_tree(pdict, c, parent=cpn)
            else:
                logging.warning('unknown <process_tree> tag: %s'%c.tag)

def __handle_process(p, pdict, bundle):
    pid = p.get('pid')
    if not pid in pdict:
        logging.warning('found <process> in <process_list> and not in <process_tree>, ignored - pid: %s'%pid)
        return
    pnode = pdict[pid]

    # process_activity
    process_activity = p.xpath('process_activity')
    if len(process_activity) == 0:
        logging.warning('no <process_activity> in <process>')
    else:
        process_activity = process_activity[0]
        for cpa in process_activity:
            if cpa.tag == 'Create':
                child_pid = int(cpa.get('child_pid'))
                action = maecactions.process_create_action(cpa.get('child_pid'), cpa.get('child_process_image'), cpa.get('command'))

                # check and modify process nodes
                childp = [cp for cp in pnode.spawned_process if cp.pid == child_pid]
                if len(childp) == 0:
                    logging.warning('"create" process activity not included in process_tree %s'%cpa.get('child_pid'))
                else:
                    childp = childp[0]
                    childp.set_parent_action(action.id_)
                    childp.argument_list = cybox.objects.process_object.ArgumentList()
                    childp.argument_list.append(cpa.get('command'))
            else:
                logging.warning('unknown process activity %s'%cpa.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "Process Activity")

    # registry activity
    registry_activity = p.xpath('registry')
    if len(registry_activity) == 0:
        logging.warning('no <registry> in <process>')
    else:
        registry_activity = registry_activity[0]
        for cra in registry_activity:
            if cra.tag == 'Create':
                action = maecactions.registry_create_key_action(cra.get('key'), cra.get('subkey'))
            elif cra.tag == 'Set':
                action = maecactions.registry_modify_key_value_action(cra.get('key'), cra.get('subkey'), cra.get('data'))
            else:
                logging.warning('unknown registry activity %s'%cra.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "Registry Activity")

    # file activity
    file_activity = p.xpath('file')
    file_attrs = {'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256', 'type': 'file_format', 'size': 'size'}
    if len(file_activity) == 0:
        logging.warning('no <file> in <process>')
    else:
        file_activity = file_activity[0]
        for cfa in file_activity:
            if cfa.tag == 'Create':
                attrs = {}
                for a in file_attrs:
                    av = cfa.get(a)
                    if av is not None and av != 'N/A' and not av.endswith('Empty'):
                        attrs[file_attrs[a]] = av.strip()
                action = maecactions.file_create_action(cfa.get('name'), attrs)
            elif cfa.tag == 'Delete':
                attrs = {}
                for a in file_attrs:
                    av = cfa.get(a)
                    if av is not None and av != 'N/A':
                        attrs[file_attrs[a]] = av.strip()
                action = maecactions.file_delete_action(cfa.get('name'), attrs)                
            else:
                logging.warning('unknown file activity %s'%cfa.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "File Activity")

    # service activity
    service_activity = p.xpath('service')
    if len(service_activity) == 0:
        logging.warning('no <service> in <process>')
    else:
        service_activity = service_activity[0]
        for csa in service_activity:
            if csa.tag == 'Create':
                action = maecactions.service_create_action(csa.get('name'), csa.get('path'))
            elif csa.tag == 'Start':
                action = maecactions.service_create_action(csa.get('name'), csa.get('path'))
            else:
                logging.warning('unknown service activity %s'%csa.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "Service Activity")

    # mutex activity
    mutex_activity = p.xpath('mutex')
    if len(mutex_activity) == 0:
        logging.warning('no <mutex> in <process>')
    else:
        mutex_activity = mutex_activity[0]
        for cma in mutex_activity:
            if cma.tag == 'CreateMutex':
                action = maecactions.mutex_create_action(cma.get('name'))
            else:
                logging.warning('unknown mutex activity %s'%cma.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "Mutex Activity")

    # java activity
    java_api_activity = p.xpath('java_api')
    if len(java_api_activity) == 0:
        logging.warning('no <java_api> in <process>')
    else:
        java_api_activity = java_api_activity[0]
        for cja in java_api_activity:
            if cja.tag == 'Java_Runtime_API_Log':
                action = maecactions.java_api_call_action(cja.get('Method'), cja.get('Arguments'))
            else:
                logging.warning('unknown java api activity %s'%cja.tag)
                continue
            pnode.add_initiated_action(action.id_)
            bundle.add_action(action, "Java Activity")

def add_dynamic_malware_analysis_from_report(csubject, report, pcap=None):
    # analysis
    wfanalysis = maec.package.analysis.Analysis(method="dynamic", type="triage")
    now = datetime.datetime.utcnow()
    wfanalysis.lastupdate_datetime = now.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00") # 2014-02-20T09:00:00.000000

    # summary with verdict
    wfsummary = "Palo Alto Networks Wildfire dynamic analysis of the malware instance object."
    software = report.xpath('software/text()')
    if len(software) > 0:
        software = software[0].strip()
        wfsummary = wfsummary+" Software: "+software+"."
    verdict = report.xpath('malware/text()')
    if len(verdict) > 0:
        verdict = verdict[0].strip()
        wfsummary += " Malware: "+verdict
    wfanalysis.summary = wfsummary

    # XXX ??? analysis environemnt ??? maybe to specify Wildfire sandbox contents
    wftool = cybox.common.ToolInformation()
    wftool.vendor = "http://www.paloaltonetworks.com"
    wftool.name = "Palo Alto Networks Wildfire"
    wftool.version = "3.0"
    wfanalysis.add_tool(wftool)

    # create the bundle
    wfbundle = maec.bundle.bundle.Bundle(defined_subject=False)
    processes = {}

    # add behaviors from report <summary> to <behavior>s
    summary = report.xpath('summary')
    if len(summary) == 0:
        logging.warning('no <summary> objects in report')
    else:
        summary = summary[0]
        for sentry in summary:
            edesc = sentry.text.strip()
            if sentry.get('details') is not None:
                edesc += " Details: "+sentry.get('details').strip()
            cb = maec.bundle.behavior.Behavior(description=edesc)
            wfbundle.add_behavior(cb)

    # process_tree
    process_tree = report.xpath('process_tree')
    if len(process_tree) == 0:
        logging.warning('no <process_tree> in report')
    else:
        if len(process_tree) > 1:
            logging.warning('multiple <process_tree> in report, only the first will be analyzed')
        process_tree = process_tree[0]
        processes['-1'] = maec.bundle.process_tree.ProcessTreeNode()
        processes['-1'].name = "Fake Root Process"
        __analyze_process_tree(processes, process_tree, processes['-1'])
    processtree = maec.bundle.process_tree.ProcessTree()
    processtree.set_root_process(processes['-1'])
    wfbundle.process_tree = processtree    

    # process_list
    wfbundle.add_named_action_collection("Process Activity")
    wfbundle.add_named_action_collection("Registry Activity")
    wfbundle.add_named_action_collection("File Activity")
    wfbundle.add_named_action_collection("Service Activity")
    wfbundle.add_named_action_collection("Mutex Activity")
    wfbundle.add_named_action_collection("Java Activity")

    process_list = report.xpath('process_list')
    if len(process_list) == 0:
        logging.warning('no <process_list> in report')
    else:
        if len(process_list) > 1:
            logging.warning('multiple <process_list> in report, only the first will be analyzed')
        process_list = process_list[0]
        for cp in process_list:
            if cp.tag != 'process':
                logging.warning('unknown tag in process_list: %s'%cp.tag)
                continue
            __handle_process(cp, processes, wfbundle)

    # network
    wfbundle.add_named_action_collection("Network Activity")
    network_activity = report.xpath('network')
    if len(network_activity) == 0:
        logging.warning('no <network> in <report>')
    else:
        network_activity = network_activity[0]
        for cna in network_activity:
            if cna.tag == 'TCP':
                action = maecactions.network_tcp_action({'ip': cna.get('ip'), 
                                            'port': cna.get('port'), 
                                            'country': cna.get('country')})
            elif cna.tag == 'UDP':
                action = maecactions.network_udp_action({'ip': cna.get('ip'), 
                                            'port': cna.get('port'), 
                                            'country': cna.get('country')})                
            elif cna.tag == 'url':
                action = maecactions.network_url_action({'host': cna.get('host'), 
                                            'method': cna.get('method'),
                                            'uri': cna.get('uri'),
                                            'user_agent': cna.get('user_agent')})
            elif cna.tag == 'dns':
                action = maecactions.network_dns_query_action({'qname': cna.get('query'), 
                                                                'qtype': cna.get('type'),
                                                                'response': cna.get('response')})
            else:
                logging.warning('unknown network activity %s - ignored'%cna.tag)
                continue
            wfbundle.add_action(action, "Network Activity")

    # pcap
    if pcap is not None:
        platform = report.xpath('platform/text()')
        if len(platform) == 0:
            logging.warning('no <platform> in <report>')
        else:
            platform = platform[0].strip()
            rao = pcap(platform)
            if rao is not None:
                wfbundle.add_named_object_collection("Network Traffic")
                wfbundle.add_object(rao, "Network Traffic")

    wfanalysis.set_findings_bundle(wfbundle.id_)
    csubject.add_analysis(wfanalysis)
    csubject.add_findings_bundle(wfbundle)

def add_static_malware_analysis_from_report(csubject, report, pcap=None):
    # analysis
    wfanalysis = maec.package.analysis.Analysis(method="static", type="triage")
    now = datetime.datetime.utcnow()
    wfanalysis.lastupdate_datetime = now.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00") # 2014-02-20T09:00:00.000000

    # summary with verdict
    wfsummary = "Palo Alto Networks Wildfire static analysis of the malware instance object."
    software = report.xpath('software/text()')
    if len(software) > 0:
        software = software[0].strip()
        wfsummary = wfsummary+" Software: "+software+"."
    verdict = report.xpath('malware/text()')
    if len(verdict) > 0:
        verdict = verdict[0].strip()
        wfsummary += " Malware: "+verdict
    wfanalysis.summary = wfsummary

    # XXX ??? analysis environemnt ??? maybe to specify Wildfire sandbox contents
    wftool = cybox.common.ToolInformation()
    wftool.vendor = "http://www.paloaltonetworks.com"
    wftool.name = "Palo Alto Networks Wildfire"
    wftool.version = "3.0"
    wfanalysis.add_tool(wftool)

    # create the bundle
    wfbundle = maec.bundle.bundle.Bundle(defined_subject=False)
    processes = {}

    # add behaviors from report <summary> to <behavior>s
    summary = report.xpath('summary')
    if len(summary) == 0:
        logging.warning('no <summary> objects in report')
    else:
        summary = summary[0]
        for sentry in summary:
            cb = maec.bundle.behavior.Behavior(description=sentry.text.strip())
            wfbundle.add_behavior(cb)

    wfanalysis.set_findings_bundle(wfbundle.id_)
    csubject.add_analysis(wfanalysis)
    csubject.add_findings_bundle(wfbundle)    

def add_malware_analysis_from_report(csubject, report, pcap=None):
    static_analysis_platforms = ['100', '101', '102', '104']

    platform = report.xpath('platform/text()')
    if len(platform) == 0:
        logging.warning('no <platform> in <report>, let\'s try with a dynamic analysis')
        return add_dynamic_malware_analysis_from_report(csubject, report, pcap)
    platform = platform[0].strip()
    if platform in static_analysis_platforms:
        return add_static_malware_analysis_from_report(csubject, report, pcap)
    return add_dynamic_malware_analysis_from_report(csubject, report, pcap)
