"""
 * Licensed to DSecure.me under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. DSecure.me licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
"""

import logging
import uuid
from typing import Dict, List

from defusedxml.lxml import RestrictedElement
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.scanners.models import Config
from vmc.scanners.parsers import Parser
from vmc.assets.documents import AssetDocument
from vmc.common.xml import iter_elements_by_name, get_root_element
from vmc.knowledge_base.documents import CveDocument
import netaddr


LOGGER = logging.getLogger(__name__)


def get_value(item: RestrictedElement) -> str:
    try:
        return item.text
    except AttributeError:
        return ''


class AssetFactory:

    @staticmethod
    def create(item: RestrictedElement, config) -> AssetDocument:
        ip_address = item.find(".//tag[@name='host-ip']").text
        return AssetDocument.get_or_create(ip_address, config)


class NessusReportParser(Parser):
    INFO = '0'
    TRASH_FOLDER_TYPE = 'trash'

    def __init__(self, config: Config):
        self.__config = config
        self.__parsed = dict()
        self.__scanned_hosts = list()

    @staticmethod
    def get_scans_ids(scan_list: Dict) -> List:
        return [x['id'] for x in scan_list['scans']
                if x['folder_id'] != NessusReportParser.get_trash_folder_id(scan_list)]

    @staticmethod
    def get_trash_folder_id(scan_list: Dict) -> [int, None]:
        if 'folders' in scan_list:
            for folder in scan_list['folders']:
                if folder['type'] == NessusReportParser.TRASH_FOLDER_TYPE:
                    return folder['id']
        return scan_list

    def parse(self, report) -> [Dict, Dict, netaddr.IPSet]:
        vuln = dict()
        for host in iter_elements_by_name(report, "ReportHost"):
            self.__scanned_hosts.append(host.get('name'))
            for item in host.iter('ReportItem'):
                vuln['asset'] = AssetFactory.create(host, self.__config)
                vuln['plugin_id'] = item.get('pluginID')
                for cve in item.findall('cve'):
                    vuln['cve_id'] = get_value(cve)
                    if item.get('severity') != NessusReportParser.INFO and vuln['cve_id']:
                        vuln['cve'] = CveDocument.get_or_create(cve_id=vuln['cve_id'])
                        vuln['port'] = item.get('port')

                        if vuln['port'] != '0':
                            vuln['svc_name'] = item.get('svc_name')
                            vuln['protocol'] = item.get('protocol')
                        else:
                            vuln['port'] = None
                            vuln['svc_name'] = None
                            vuln['protocol'] = None
                        vuln['description'] = get_value(item.find('description'))
                        vuln['solution'] = get_value(item.find('solution'))
                        vuln['exploit_available'] = True if get_value(item.find('exploit_available')) == 'true' else False
                        vuln['id'] = self._vuln_id(vuln['asset'].ip_address, vuln['protocol'], vuln['plugin_id'])
                        self._create(vuln)
        return self.__parsed, self.__scanned_hosts

    def _create(self, item: dict):
        vuln = VulnerabilityDocument()
        for field in VulnerabilityDocument.get_fields_name():
            if field in item:
                try:
                    setattr(vuln, field, item[field])
                except (KeyError, IndexError):
                    setattr(vuln, field, 'UNKNOWN')
        vuln.tags = ['Nessus']
        self.__parsed[vuln.id] = vuln

    @staticmethod
    def _vuln_id(ip, protocol, plugin_id) -> str:
        key = F"{ip}-{protocol}-{plugin_id}"
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))

    @staticmethod
    def get_targets(file):
        root = get_root_element(file)
        targets = netaddr.IPSet()
        for preference in root.findall(".//Preferences/ServerPreferences/preference"):
            if preference[0].tag == "name" and preference[0].text == "TARGET":
                for target in map(str.strip, preference[1].text.split(sep=",")):
                    if not "-" in target:
                        targets.add(target)
                    else:
                        ip_range = target.split(sep="-")
                        targets.add(netaddr.IPRange(ip_range[0], ip_range[1]))
                return targets
