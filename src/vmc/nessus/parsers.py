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

from vmc.assets.models import Asset, Port
from vmc.common.xml import iter_elements_by_name
from vmc.knowledge_base.models import Cve
from vmc.vulnerabilities.models import Vulnerability


LOGGER = logging.getLogger(__name__)


def get_value(item: RestrictedElement) -> str:
    try:
        return item.text
    except AttributeError:
        return ''


class AssetFactory:

    @staticmethod
    def create(item: RestrictedElement) -> Asset:
        os = get_value(item.find(".//tag[@name='operating-system']"))
        asset, _ = Asset.objects.get_or_create(
            ip_address=item.find(".//tag[@name='host-ip']").text,
            mac_address=get_value(item.find(".//tag[@name='mac-address']")),
            os=os if os else 'Unknown'
        )
        return asset


class ReportParser:
    INFO = '0'

    @staticmethod
    def parse(xml_root) -> None:
        for host in iter_elements_by_name(xml_root, 'ReportHost'):
            for item in host.iter('ReportItem'):
                asset = AssetFactory.create(host)
                cve_id = get_value(item.find('cve'))

                if item.get('severity') != ReportParser.INFO and cve_id:
                    cve, _ = Cve.objects.get_or_create(id=cve_id)
                    port_number = item.get('port')

                    if port_number != 0:
                        port, _ = Port.objects.get_or_create(
                            number=port_number,
                            svc_name=item.get('svc_name'),
                            protocol=item.get('protocol')
                        )
                    else:
                        port = None

                    Vulnerability.objects.create(
                        asset=asset,
                        cve=cve,
                        port=port,
                        description=get_value(item.find('description')),
                        solution=get_value(item.find('solution')),
                        exploit_available=True if get_value(item.find('exploit_available')) == 'true' else False
                    )
