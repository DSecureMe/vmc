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
    def create(item: RestrictedElement) -> AssetDocument:
        ip_address = item.find(".//tag[@name='host-ip']").text
        result = AssetDocument.search().filter('term', ip_address=ip_address).sort('-modified_date').execute()
        if result.hits:
            return result.hits[0]
        asset = AssetDocument(ip_address=ip_address)
        asset.save(refresh=True)
        return asset


class ReportParser:
    INFO = '0'

    @staticmethod
    def parse(xml_root) -> None:
        for host in iter_elements_by_name(xml_root, 'ReportHost'):
            for item in host.iter('ReportItem'):
                asset = AssetFactory.create(host)

                for cve in item.findall('cve'):
                    cve_id = get_value(cve)
                    if item.get('severity') != ReportParser.INFO and cve_id:
                        cve = ReportParser.get_or_create_cve(cve_id=cve_id)
                        port_number = item.get('port')

                        if port_number != 0:
                            svc_name = item.get('svc_name')
                            protocol = item.get('protocol')
                        else:
                            port_number = None
                            svc_name = None
                            protocol = None
                        VulnerabilityDocument(
                            asset=asset,
                            cve=cve,
                            port=port_number,
                            svc_name=svc_name,
                            protocol=protocol,
                            description=get_value(item.find('description')),
                            solution=get_value(item.find('solution')),
                            exploit_available=True if get_value(item.find('exploit_available')) == 'true' else False
                        ).save(refresh=True)

    @staticmethod
    def get_or_create_cve(cve_id: str) -> CveDocument:
        result = CveDocument.search().filter('term', id=cve_id).sort('-modified_date').execute()
        if result.hits:
            return result.hits[0]
        cve = CveDocument(id=cve_id)
        cve.save(refresh=True)
        return cve
