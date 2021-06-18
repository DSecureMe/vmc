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
import re
import logging
import uuid
import netaddr
from typing import Dict, List
from datetime import datetime

from defusedxml.lxml import RestrictedElement
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.scanners.models import Config
from vmc.scanners.parsers import Parser
from vmc.assets.documents import AssetDocument
from vmc.common.xml import iter_elements_by_name, get_root_element
from vmc.knowledge_base.documents import CveDocument
from vmc.knowledge_base import metrics


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
        mac_address = get_value(item.find(".//tag[@name='mac-address']"))
        return AssetDocument.get_or_create(ip_address, mac_address, config)


class NessusReportParser(Parser):
    INFO = '0'
    TRASH_FOLDER_TYPE = 'trash'

    def __init__(self, config: Config):
        self.__config = config
        self.__parsed = dict()
        self.__scanned_hosts = list()

    def get_scans_ids(self, reports) -> List:
        if reports['scans']:
            folders = self._get_folders(reports)
            return [x['id'] for x in reports['scans'] if x['folder_id'] in folders]
        return []

    def _get_folders(self, scan_list: Dict) -> [int, None]:
        result = set()
        if 'folders' in scan_list:
            for folder in scan_list['folders']:
                if folder['type'] != NessusReportParser.TRASH_FOLDER_TYPE and self._match_folder(
                        self.__config.filter, folder['name']):
                    result.add(folder['id'])
        return result

    @staticmethod
    def _match_folder(folder_filter, name):
        if folder_filter:
            return re.match(folder_filter, name)
        return True

    def parse(self, report, file_url) -> [Dict, Dict]:
        for host in iter_elements_by_name(report, "ReportHost"):
            scan_date = host.find('HostProperties/tag[@name="HOST_START_TIMESTAMP"]').text
            scan_date = datetime.fromtimestamp(int(scan_date))

            asset = AssetFactory.create(host, self.__config)
            asset.last_scan_date = scan_date
            self.__scanned_hosts.append(asset)

            for item in host.iter('ReportItem'):
                if item.get('severity') != NessusReportParser.INFO:
                    vuln = dict()
                    vuln['scan_date'] = scan_date
                    vuln['scan_file_url'] = file_url
                    vuln['asset'] = asset
                    vuln['plugin_id'] = item.get('pluginID')
                    vuln['name'] = item.get('pluginName')
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

                    vuln['tenant'] = self.__config.tenant.name if self.__config.tenant else None
                    cves = item.findall('cve')
                    if cves:
                        for cve in cves:
                            vuln['cve_id'] = get_value(cve)
                            vuln['cve'] = CveDocument.get_or_create(cve_id=vuln['cve_id'])
                            vuln['id'] = self._vuln_id(vuln, vuln['cve_id'])
                            self._create(vuln)
                    else:
                        vuln['cve'] = self._create_nessus_cve(item)
                        vuln['id'] = self._vuln_id(vuln, vuln['cve'].id)
                        self._create(vuln)

        return self.__parsed, self.__scanned_hosts

    def _create_nessus_cve(self, item):
        cve = CveDocument()
        cve.id = 'NESSUS-{}'.format(item.get('pluginID'))

        base_score_v2 = get_value(item.find('cvss_base_score'))
        if base_score_v2:
            cve.base_score_v2 = float(base_score_v2)

        base_score_v3 = get_value(item.find('cvss3_base_score'))
        if base_score_v3:
            cve.base_score_v3 = float(base_score_v3)

        cve = self._create_nessus_cve_cvss3_vector(item, cve)
        cve = self._create_nessus_cve_cvss_vector(item, cve)
        return cve

    @staticmethod
    def _create_nessus_cve_cvss3_vector(item, cve):
        cvss3_vector = get_value(item.find('cvss3_vector'))
        if cvss3_vector:
            cvss3_vector = NessusReportParser.parse_vector(cvss3_vector, 'CVSS:3.0/')
            cve.attack_vector_v3 = metrics.AttackVectorV3(cvss3_vector['AV'])
            cve.attack_complexity_v3 = metrics.AttackComplexityV3(cvss3_vector['AC'])
            cve.privileges_required_v3 = metrics.PrivilegesRequiredV3(cvss3_vector['PR'])
            cve.user_interaction_v3 = metrics.UserInteractionV3(cvss3_vector['UI'])
            cve.scope_v3 = metrics.ScopeV3(cvss3_vector['S'])
            cve.confidentiality_impact_v3 = metrics.ImpactV3(cvss3_vector['C'])
            cve.integrity_impact_v3 = metrics.ImpactV3(cvss3_vector['I'])
            cve.availability_impact_v3 = metrics.ImpactV3(cvss3_vector['A'])
        return cve

    @staticmethod
    def _create_nessus_cve_cvss_vector(item, cve):
        cvss_vector = get_value(item.find('cvss_vector'))
        if cvss_vector:
            cvss_vector = NessusReportParser.parse_vector(cvss_vector, 'CVSS2#')
            cve.access_vector_v2 = metrics.AccessVectorV2(cvss_vector['AV'])
            cve.access_complexity_v2 = metrics.AccessComplexityV2(cvss_vector['AC'])
            cve.authentication_v2 = metrics.AuthenticationV2(cvss_vector['Au'])
            cve.confidentiality_impact_v2 = metrics.ImpactV2(cvss_vector['C'])
            cve.integrity_impact_v2 = metrics.ImpactV2(cvss_vector['I'])
            cve.availability_impact_v2 = metrics.ImpactV2(cvss_vector['A'])

        return cve

    @staticmethod
    def parse_vector(vector, version):
        cvss_vector = vector.replace(version, '')
        cvss_vector = cvss_vector.split('/')
        cvss_vector = [v.split(':') for v in cvss_vector]
        return {v[0]: v[1] for v in cvss_vector}

    def _create(self, item: dict):
        vuln = VulnerabilityDocument()
        for field in VulnerabilityDocument.get_fields_name():
            if field in item:
                try:
                    setattr(vuln, field, item[field])
                except (KeyError, IndexError):
                    setattr(vuln, field, 'UNKNOWN')
        vuln.source = 'Nessus'
        self.__parsed[vuln.id] = vuln

    @staticmethod
    def _vuln_id(vuln, cve_id) -> str:
        key = F"{vuln['asset'].ip_address}-{vuln['protocol']}-{vuln['port']}-{vuln['plugin_id']}-{cve_id}"
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))

    @staticmethod
    def get_targets(file):
        root = get_root_element(file)
        targets = netaddr.IPSet()
        for preference in root.findall(".//Preferences/ServerPreferences/preference"):
            if preference[0].tag == "name" and preference[0].text == "TARGET":
                for target in map(str.strip, preference[1].text.split(sep=",")):
                    if "-" not in target:
                        targets.add(target)
                    else:
                        ip_range = target.split(sep="-")
                        targets.add(netaddr.IPRange(ip_range[0], ip_range[1]))
                return targets
