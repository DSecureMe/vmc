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
import defusedxml.ElementTree as ET
from typing import List, Dict

from vmc.knowledge_base import metrics
from vmc.knowledge_base.utils import calculate_base_score_v2

from vmc.scanners.parsers import Parser
from vmc.scanners.models import Config
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.assets.documents import AssetDocument
from vmc.knowledge_base.documents import CveDocument


def _vuln_id(ip, port, oid, cve_id) -> str:
    key = F"{ip}-{port}-{oid}-{cve_id}"
    return str(uuid.uuid3(uuid.NAMESPACE_OID, key))


def _parse_tags(tags):
    return dict(x.split("=", 1) for x in tags.split("|"))


def _create_ovasp_cve(oid, tags):
    cve = CveDocument()
    cve.id =  F'NOCVE-{oid}'

    vector = tags['cvss_base_vector']
    vector = dict(x.split(':') for x in vector.split('/'))
    cve.access_vector_v2 = metrics.AccessVectorV2(vector['AV'])
    cve.access_complexity_v2 = metrics.AccessComplexityV2(vector['AC'])
    cve.authentication_v2 = metrics.AuthenticationV2(vector['Au'])
    cve.confidentiality_impact_v2 = metrics.ImpactV2(vector['C'])
    cve.integrity_impact_v2 = metrics.ImpactV2(vector['I'])
    cve.availability_impact_v2 = metrics.ImpactV2(vector['A'])
    cve.base_score_v2 = calculate_base_score_v2(cve)
    return cve


class GmpParserOMP7(Parser):

    def __init__(self, config: Config):
        self._config = config
        self.__parsed = dict()
        self.__scanned_host = dict()

    def get_scans_ids(self, reports) -> List:
        return [r.attrib.get('id') for r in reports.findall('report') if r.attrib.get('type') == 'scan']

    def parse(self, report, file_url) -> [Dict, Dict]:
        report = ET.fromstring(report.read())
        for r in report.findall('.//results/result'):
            ip_address = r.find('./host').text.strip()
            scan_date = r.find('./creation_time').text

            if ip_address not in self.__scanned_host:
                asset = AssetDocument.get_or_create(ip_address, config=self._config)
                self.__scanned_host[ip_address] = asset
            else:
                asset = self.__scanned_host[ip_address]

            asset.last_scan_date = scan_date

            if float(r.find('nvt//cvss_base').text) > 0:
                name = r.find('./name').text
                tags = _parse_tags(r.find('./nvt/tags').text)
                for cve in r.find('./nvt//cve').text.split(','):
                    port = r.find('./port').text.split('/')[0]
                    protocol = r.find('./port').text.split('/')[1]
                    oid = r.find('./nvt').attrib.get('oid')
                    cve = self.get_cve(cve, oid, tags)
                    if port == 'general':
                        port = None
                        protocol = None
                    uid = _vuln_id(ip_address, port, oid, cve.id)
                    self.__parsed[uid] = VulnerabilityDocument(
                        id=uid,
                        port=port,
                        protocol=protocol,
                        name=name,
                        description=r.find('./description').text,
                        solution=tags['solution'],
                        cve=cve,
                        asset=asset,
                        tenant=self._config.tenant.name if self._config.tenant else None,
                        source='OpenVas',
                        scan_file_url=file_url,
                        scan_date=scan_date
                    )

        return self.__parsed, list(self.__scanned_host.values())

    @staticmethod
    def get_cve(cve_id, oid, tags):
        if cve_id == 'NOCVE':
            return _create_ovasp_cve(oid, tags)
        return CveDocument.get_or_create(cve_id=cve_id)


class GMP9Parser(Parser):

    def __init__(self, config: Config):
        self._config = config
        self.__parsed = dict()
        self.__scanned_host = dict()

    def get_scans_ids(self, reports) -> List:
        return [r.attrib.get('id') for r in reports.findall('report') if r.attrib.get('content_type') == 'text/xml']

    def parse(self, report, file_url) -> [Dict, Dict]:
        report = ET.fromstring(report.read())
        for r in report.findall('.//results/result'):
            ip_address = r.find('./host').text.strip()
            scan_date = r.find('./creation_time').text

            if ip_address not in self.__scanned_host:
                asset = AssetDocument.get_or_create(ip_address, config=self._config)
                self.__scanned_host[ip_address] = asset
            else:
                asset = self.__scanned_host[ip_address]

            asset.last_scan_date = scan_date

            if float(r.find('nvt//cvss_base').text) > 0:
                name = r.find('./name').text
                tags = _parse_tags(r.find('./nvt/tags').text)
                for cve in self._get_cves(r, tags):
                    port = r.find('./port').text.split('/')[0]
                    protocol = r.find('./port').text.split('/')[1]
                    oid = r.find('./nvt').attrib.get('oid')
                    if port == 'general':
                        port = None
                        protocol = None
                    uid = _vuln_id(ip_address, port, oid, cve.id)
                    self.__parsed[uid] = VulnerabilityDocument(
                        id=uid,
                        port=port,
                        protocol=protocol,
                        name=name,
                        description=r.find('./description').text,
                        solution=tags['solution'],
                        cve=cve,
                        asset=asset,
                        tenant=self._config.tenant.name if self._config.tenant else None,
                        source='OpenVas',
                        scan_file_url=file_url,
                        scan_date=scan_date
                    )

        return self.__parsed, list(self.__scanned_host.values())

    @staticmethod
    def _get_cves(element, tags):
        cves = GMP9Parser._parse_cves(element)
        if not cves:
            oid = element.find('./nvt').attrib.get('oid')
            return [_create_ovasp_cve(oid, tags)]
        return [CveDocument.get_or_create(cve_id=c) for c in cves]


    @staticmethod
    def _parse_cves(element):
        cvss = [x.attrib['id'] for x in element.findall('.//ref[@type="cve"]')]
        return cvss