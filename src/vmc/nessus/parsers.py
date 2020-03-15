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


class ReportParser:
    INFO = '0'

    @staticmethod
    def parse(xml_root, config) -> None:
        index = VulnerabilityDocument.get_index(config)
        for host in iter_elements_by_name(xml_root, 'ReportHost'):
            for item in host.iter('ReportItem'):
                asset = AssetFactory.create(host, config)
                plugin_id = item.get('pluginID')
                for cve in item.findall('cve'):
                    cve_id = get_value(cve)
                    if item.get('severity') != ReportParser.INFO and cve_id:
                        cve = CveDocument.get_or_create(cve_id=cve_id)
                        port_number = item.get('port')

                        if port_number != 0:
                            svc_name = item.get('svc_name')
                            protocol = item.get('protocol')
                        else:
                            port_number = None
                            svc_name = None
                            protocol = None
                        VulnerabilityDocument(
                            plugin_id=plugin_id,
                            asset=asset,
                            cve=cve,
                            port=port_number,
                            svc_name=svc_name,
                            protocol=protocol,
                            description=get_value(item.find('description')),
                            solution=get_value(item.find('solution')),
                            exploit_available=True if get_value(item.find('exploit_available')) == 'true' else False
                        ).save(index=index, refresh=True)


class ScanParser:
    INFO = '0'

    def __init__(self, config: Config):
        self.__config = config
        self.__parsed = dict()

    def parse(self, xml_root, config):
        vuln = dict()
#        index = VulnerabilityDocument.get_index(config)
        for host in iter_elements_by_name(xml_root, 'ReportHost'):
            for item in host.iter('ReportItem'):
                vuln['asset'] = AssetFactory.create(host, config)
                vuln['plugin_id'] = item.get('pluginID')
                for cve in item.findall('cve'):
                    vuln['cve_id'] = get_value(cve)
                    if item.get('severity') != ReportParser.INFO and vuln['cve_id']:
                        vuln['cve'] = CveDocument.get_or_create(cve_id=vuln['cve_id'])
                        vuln['port_number'] = item.get('port')

                        if vuln['port_number'] != 0:
                            vuln['svc_name'] = item.get('svc_name')
                            vuln['protocol'] = item.get('protocol')
                        else:
                            vuln['port_number'] = None
                            vuln['svc_name'] = None
                            vuln['protocol'] = None
                        vuln.id = id(vuln['asset'].ip_address, vuln['protocol'], vuln['plugin_id'])
                        self.create(vuln)
        return self.__parsed

    def create(self, item: dict):
        vuln = VulnerabilityDocument()
        for field in VulnerabilityDocument.get_fields_name():
            parser = getattr(item, field, None)
            try:
                if parser:
                    setattr(vuln, field, item[field])
            except (KeyError, IndexError):
                setattr(vuln, field, 'UNKNOWN')
        self.__parsed[vuln.id] = vuln

    def id(self, ip, protocol, plugin_id) -> str:
        key = F"{ip}-{protocol}-{plugin_id}"
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))
