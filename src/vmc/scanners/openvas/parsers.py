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

import uuid
from typing import List, Dict

from vmc.knowledge_base import metrics
from vmc.knowledge_base.utils import calculate_base_score_v2

from vmc.scanners.parsers import Parser
from vmc.scanners.models import Config
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.assets.documents import AssetDocument
from vmc.knowledge_base.documents import CveDocument


class GmpParser(Parser):

    def __init__(self, config: Config):
        self._config = config
        self.__parsed = dict()
        self.__scanned_host = list()

    @staticmethod
    def get_scans_ids(reports) -> List:
        return [r.attrib.get('id') for r in reports.findall('report') if r.attrib.get('type') == 'scan']

    def parse(self, report) -> [Dict, Dict]:
        for r in report.findall('.//results/result'):
            if float(r.find('nvt//cvss_base').text) > 0:
                ip_address = r.find('./host').text
                self.__scanned_host.append(ip_address)
                asset = AssetDocument.get_or_create(ip_address, self._config)
                tags = self.parse_tags(r.find('./nvt/tags').text)
                for cve in r.find('./nvt//cve').text.split(','):
                    port = r.find('./port').text.split('/')[0]
                    protocol = r.find('./port').text.split('/')[1]
                    oid = r.find('./nvt').attrib.get('oid')
                    cve = self.get_cve(cve, oid, tags)
                    if port == 'general':
                        port = None
                        protocol = None
                    uid = self._vuln_id(ip_address, port, oid)
                    self.__parsed[uid] = VulnerabilityDocument(
                        id=uid,
                        port=port,
                        protocol=protocol,
                        description=r.find('./description').text,
                        solution=tags['solution'],
                        cve=cve,
                        asset=asset,
                        source='OpenVas'
                    )

        return self.__parsed, self.__scanned_host

    @staticmethod
    def _vuln_id(ip, port, oid) -> str:
        key = F"{ip}-{port}-{oid}"
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))

    @staticmethod
    def parse_tags(tags):
        return dict(x.split("=", 1) for x in tags.split("|"))

    def get_asset(self, ip_address):
        return AssetDocument.get_or_create(ip_address, self._config)

    @staticmethod
    def get_cve(cve_id, oid, tags):

        if cve_id == 'NOCVE':
            cve_id = F'NOCVE-{oid}'
            cve = CveDocument.get_or_create(cve_id=cve_id)

            vector = tags['cvss_base_vector']
            vector = dict(x.split(':') for x in vector.split('/'))
            new_cve = CveDocument(id=cve_id)
            new_cve.access_vector_v2 = metrics.AccessVectorV2(vector['AV'])
            new_cve.access_complexity_v2 = metrics.AccessComplexityV2(vector['AC'])
            new_cve.authentication_v2 = metrics.AuthenticationV2(vector['Au'])
            new_cve.confidentiality_impact_v2 = metrics.ImpactV2(vector['C'])
            new_cve.integrity_impact_v2 = metrics.ImpactV2(vector['I'])
            new_cve.availability_impact_v2 = metrics.ImpactV2(vector['A'])
            new_cve.base_score_v2 = calculate_base_score_v2(new_cve)
            if cve.has_changed(new_cve):
                return cve.update(new_cve, refresh=True)
            return cve

        return CveDocument.get_or_create(cve_id=cve_id)
