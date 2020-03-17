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

from defusedxml.lxml import RestrictedElement
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.nessus.models import Config
from vmc.assets.documents import AssetDocument
from vmc.common.xml import iter_elements_by_name
from vmc.knowledge_base.documents import CveDocument


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


class ScanParser:
    INFO = '0'

    def __init__(self, config: Config):
        self.__config = config
        self.__parsed = dict()
        self.__scanned_hosts = list()

    def parse(self, xml_root, config):
        vuln = dict()
        for host in iter_elements_by_name(xml_root, 'ReportHost'):
            self.__scanned_hosts.append(host.get('name'))
            for item in host.iter('ReportItem'):
                vuln['asset'] = AssetFactory.create(host, config)
                vuln['plugin_id'] = item.get('pluginID')
                for cve in item.findall('cve'):
                    vuln['cve_id'] = get_value(cve)
                    if item.get('severity') != ScanParser.INFO and vuln['cve_id']:
                        vuln['cve'] = CveDocument.get_or_create(cve_id=vuln['cve_id'])
                        vuln['port'] = item.get('port')

                        if vuln['port'] != 0:
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
                        self.create(vuln)
        return self.__parsed, self.__scanned_hosts

    def create(self, item: dict):
        vuln = VulnerabilityDocument()
        for field in VulnerabilityDocument.get_fields_name():
            if field in item:
                try:
                    setattr(vuln, field, item[field])
                except (KeyError, IndexError):
                    setattr(vuln, field, 'UNKNOWN')
        self.__parsed[vuln.id] = vuln

    @staticmethod
    def _vuln_id(ip, protocol, plugin_id) -> str:
        key = F"{ip}-{protocol}-{plugin_id}"
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))
