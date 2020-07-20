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
import datetime
import netaddr
from unittest import skipIf
from unittest.mock import patch

from django.test import TestCase


from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.nessus.parsers import NessusReportParser
from vmc.scanners.nessus.apps import NessusConfig
from vmc.scanners.nessus.clients import NessusClient


from vmc.knowledge_base import metrics
from vmc.config.test_settings import elastic_configured
from vmc.elasticsearch.tests import ESTestCase


from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.common.tests import get_fixture_location


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


class NessusConfigTest(TestCase):
    fixtures = ['nessus_config.json']

    def test_name(self):
        self.assertEqual(NessusConfig.name, 'vmc.scanners.nessus')

    def test_registry(self):
        config = Config.objects.first()
        self.assertIsInstance(scanners_registry.get_parser(config), NessusReportParser)
        self.assertIsInstance(scanners_registry.get_client(config), NessusClient)


class NessusClientTest(TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        self.config = Config.objects.first()
        self.uut = NessusClient(self.config)
        self.headers = {
            'X-ApiKeys': F'accessKey={self.config.username};secretKey={self.config.password}',
            'Content-type': 'application/json',
            'Accept': 'text/plain'
        }

    def assert_request(self, request_mock, method, action):
        request_mock.request.assert_called_with(
            method,
            F'http://test:80/{action}',
            data='{}',
            headers=self.headers,
            verify=not self.config.insecure
        )

    @patch('vmc.scanners.nessus.clients.requests')
    def test_call_get_scan_list(self, request_mock):
        request_mock.request.return_value = ResponseMock({'scan': 1}, 200)

        scan_list = self.uut.get_scans()
        self.assert_request(request_mock, 'GET', 'scans')
        self.assertEqual(scan_list, {'scan': 1})

        scan_list2 = self.uut.get_scans(last_modification_date=datetime.datetime.fromtimestamp(1551398400))
        self.assert_request(request_mock, 'GET', 'scans?last_modification_date=1551398400')
        self.assertEqual(scan_list2, {'scan': 1})

    @patch('vmc.scanners.nessus.clients.requests')
    def test_call_get_scan_detail(self, request_mock):
        request_mock.request.return_value = ResponseMock({'foo': 1}, 200)

        resp = self.uut.get_scan_detail(1)
        self.assert_request(request_mock, 'GET', 'scans/1')

        self.assertEqual(resp, {'foo': 1})


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class NessusReportParserTest(ESTestCase, TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        super().setUp()
        self.config = Config.objects.first()
        self.internal_xml = open(get_fixture_location(__file__, 'internal.xml'))
        self.internal_targets_xml = open(get_fixture_location(__file__, 'internal_targets.xml'))
        self.uut = NessusReportParser(self.config)
        self.addr1 = "192.168.1.1/32"
        self.addr2 = "192.168.1.1"
        self.addr3 = "10.0.0.1/30"
        self.addr4 = "192.168.2.1-192.168.2.5"

    def test_get_scans_ids(self):
        self.assertEqual(self.uut.get_scans_ids(
            {'scans': [
                {'id': 2, 'folder_id': 2},
                {'id': 3, 'folder_id': 1}
            ],
                'folders': [{'type': 'trash', 'id': 1}]}
        ), [2])

    def test_parse_call(self):
        parsed, scanned_hosts = self.uut.parse(self.internal_xml)
        vuln_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '10.31.2.30-tcp-70658'))
        self.assertEquals(len(parsed), 2)
        self.assertIsInstance(parsed[vuln_id], VulnerabilityDocument)
        self.assertEquals(parsed[vuln_id].asset.ip_address, '10.31.2.30')
        self.assertEquals(parsed[vuln_id].cve.id, 'CVE-2008-5161')
        self.assertEquals(parsed[vuln_id].port, '22')
        self.assertEquals(parsed[vuln_id].svc_name, 'ssh')
        self.assertEquals(parsed[vuln_id].protocol, 'tcp')
        self.assertEquals(parsed[vuln_id].solution, 'Contact the vendor or consult product documentation to disable CBC mode '
                                        'cipher encryption, and enable CTR or GCM cipher mode encryption.')
        self.assertIn('The SSH server is configured to support Cipher Block Chaining (CBC)', parsed[vuln_id].description)
        self.assertEquals(scanned_hosts, ['10.31.2.30'])

        vuln_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '10.31.2.30-tcp-42263'))
        self.assertIsInstance(parsed[vuln_id], VulnerabilityDocument)
        self.assertEquals(parsed[vuln_id].asset.ip_address, '10.31.2.30')
        self.assertEquals(parsed[vuln_id].cve.id, 'NESSUS-42263')
        self.assertEqual(parsed[vuln_id].cve.base_score_v3, 6.5)

        self.assertEqual(parsed[vuln_id].cve.attack_vector_v3, metrics.AttackVectorV3.NETWORK)
        self.assertEqual(parsed[vuln_id].cve.attack_complexity_v3, metrics.AttackComplexityV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.privileges_required_v3, metrics.PrivilegesRequiredV3.NONE)
        self.assertEqual(parsed[vuln_id].cve.user_interaction_v3, metrics.UserInteractionV3.NONE)
        self.assertEqual(parsed[vuln_id].cve.scope_v3, metrics.ScopeV3.UNCHANGED)
        self.assertEqual(parsed[vuln_id].cve.confidentiality_impact_v3, metrics.ImpactV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.integrity_impact_v3, metrics.ImpactV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.availability_impact_v3, metrics.ImpactV3.NONE)

        self.assertEqual(parsed[vuln_id].cve.base_score_v2, 5.8)
        self.assertEqual(parsed[vuln_id].cve.access_vector_v2, metrics.AccessVectorV2.NETWORK)
        self.assertEqual(parsed[vuln_id].cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM)
        self.assertEqual(parsed[vuln_id].cve.authentication_v2, metrics.AuthenticationV2.NONE)
        self.assertEqual(parsed[vuln_id].cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(parsed[vuln_id].cve.integrity_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(parsed[vuln_id].cve.availability_impact_v2, metrics.ImpactV2.NONE)


    def test__get_targets_call(self):

        multiple_targets = self.uut.get_targets(self.internal_targets_xml)

        self.assertEqual(len(multiple_targets.iter_cidrs()), 9)
        self.assertEqual(netaddr.IPNetwork("10.10.10.0/8"), multiple_targets.iter_cidrs()[0])
        self.assertEqual(netaddr.IPNetwork("192.168.1.1/32"), multiple_targets.iter_cidrs()[1])
        self.assertEqual(netaddr.IPNetwork("192.168.2.10/31"), multiple_targets.iter_cidrs()[2])
        self.assertEqual(netaddr.IPNetwork("192.168.2.12/30"), multiple_targets.iter_cidrs()[3])
        self.assertEqual(netaddr.IPNetwork("192.168.2.16/28"), multiple_targets.iter_cidrs()[4])
        self.assertEqual(netaddr.IPNetwork("192.168.2.32/27"), multiple_targets.iter_cidrs()[5])
        self.assertEqual(netaddr.IPNetwork("192.168.2.64/28"), multiple_targets.iter_cidrs()[6])
        self.assertEqual(netaddr.IPNetwork("192.168.2.80/29"), multiple_targets.iter_cidrs()[7])
        self.assertEqual(netaddr.IPNetwork("192.168.2.88/32"), multiple_targets.iter_cidrs()[8])

        ip_set = netaddr.IPSet()
        for n in range(9, 90, 1):
            ip_set.add(F"192.168.2.{n}")

        check_set = netaddr.IPSet()
        for cidr in multiple_targets.iter_cidrs()[-7:]:
            check_set.add(cidr)

        for ip in ip_set:
            if str(ip) == "192.168.2.9" or str(ip) == "192.168.2.89":
                self.assertFalse(ip in check_set)
            else:
                self.assertTrue(ip in check_set)
