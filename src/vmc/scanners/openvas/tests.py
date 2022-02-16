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
from unittest import skipIf
from unittest.mock import patch

import defusedxml.ElementTree as ET

from django.test import TestCase

from vmc.scanners.openvas.managers import OpenVasManager, OpenVasManagerException
from vmc.knowledge_base.metrics import ImpactV2, AuthenticationV2, AccessVectorV2, AccessComplexityV2
from vmc.common.xml import get_root_element
from vmc.scanners.clients import Client
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.config.test_settings import elastic_configured
from vmc.common.tests import get_fixture_location
from vmc.elasticsearch.tests import ESTestCase

from vmc.scanners.openvas.apps import OpenVasConfig
from vmc.scanners.openvas.parsers import GmpParserOMP7, GMP9Parser
from vmc.scanners.openvas.clients import OpenVasClient
from netaddr import IPSet, IPNetwork, IPRange, IPAddress


class OpenVasConfigTest(TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()
        cls.manager = scanners_registry.get(cls.config)

    def test_name(self):
        self.assertEqual(OpenVasConfig.name, 'vmc.scanners.openvas')

    def test_registry(self):
        self.assertIsInstance(self.manager, OpenVasManager)



class OpenVasManagerTest(TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()
        cls.uut = scanners_registry.get(cls.config)

    def test_get_client_call(self):
        self.assertIsInstance(self.uut.get_client(), OpenVasClient)

    @patch('vmc.scanners.openvas.managers.OpenVasClient')
    def test_get_parser_exception(self, client):
        client().get_version.return_value = None
        with self.assertRaises(OpenVasManagerException):
            self.uut.get_parser()

    @patch('vmc.scanners.openvas.managers.OpenVasClient')
    def test_omp_7_get_parser(self, client):
        client().get_version.return_value = ET.parse(get_fixture_location(__file__, 'omp_7_version.xml'))
        parser = self.uut.get_parser()
        self.assertIsInstance(parser, GmpParserOMP7)
        self.assertTrue(parser.get_targets)

    @patch('vmc.scanners.openvas.managers.OpenVasClient')
    def test_get_parser_gmp_9_call(self, client):
        client().get_version.return_value = ET.parse(get_fixture_location(__file__, 'gm_9_version.xml'))
        parser = self.uut.get_parser()
        self.assertIsInstance(parser, GMP9Parser)
        self.assertTrue(parser.get_targets)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class GmpParserOMP7Test(ESTestCase, TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()

    def test_get_reports_ids_call(self):
        xml = ET.parse(get_fixture_location(__file__, 'reports_omp_7.xml'))
        parser = GmpParserOMP7(self.config)
        ids = parser.get_scans_ids(xml)
        self.assertEqual(ids, ['0f9ea6ca-→abf5-4139-a772-cb68937cdfbb'])

    def test_parse(self):
        with open(get_fixture_location(__file__, 'report_omp_7.xml'), 'r') as file:
            parser = GmpParserOMP7(self.config)
            vulns, scanned_hosts = parser.parse(file, "report_omp_7.xml")
            self.assertEqual(len(scanned_hosts), 7)
            self.assertEqual(scanned_hosts[0].last_scan_date, '2020-04-08T21:04:47Z')
            self.assertEqual(set(['10.10.10.31', '10.10.10.30', '10.10.10.32', '10.10.10.21',
                     '10.10.10.20', '10.10.10.7', '10.10.10.23']), set(x.ip_address for x in scanned_hosts))
            self.assertEqual(len(vulns), 17)

            vuln = vulns['c2649538-c269-3902-9361-de3e3558a449']
            self.assertEqual(vuln.cve.base_score_v2, 5.0)
            self.assertEqual(vuln.cve.access_vector_v2, AccessVectorV2.NETWORK)
            self.assertEqual(vuln.cve.access_complexity_v2, AccessComplexityV2.LOW)
            self.assertEqual(vuln.cve.authentication_v2, AuthenticationV2.NONE)
            self.assertEqual(vuln.cve.confidentiality_impact_v2, ImpactV2.PARTIAL)
            self.assertEqual(vuln.cve.integrity_impact_v2, ImpactV2.NONE)
            self.assertEqual(vuln.cve.availability_impact_v2, ImpactV2.NONE)
            self.assertEqual(vuln.port, '135')
            self.assertEqual(vuln.protocol, 'tcp')
            self.assertEqual(vuln.scan_date, '2020-04-08T21:06:33Z')
            self.assertEqual(vuln.name, 'DCE/RPC and MSRPC Services Enumeration Reporting')
            self.assertEqual(vuln.solution, 'Filter incoming traffic to this ports.')
            self.assertEqual(vuln.scan_file_url, "report_omp_7.xml")


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class GMP9ParserTest(ESTestCase, TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()

    def test_get_reports_ids_call(self):
        xml = ET.parse(get_fixture_location(__file__, 'reports_gmp_9.xml'))
        parser = GMP9Parser(self.config)
        ids = parser.get_scans_ids(xml)
        self.assertEqual(ids, ['b0fd2f9e-50e5-4bb4-8af9-bff540154dcc'])

    def test_parse(self):
        with open(get_fixture_location(__file__, 'report_gmp_9.xml'), 'r') as file:
            parser = GMP9Parser(self.config)
            vulns, scanned_hosts = parser.parse(file, "report_gmp_9.xml")
            self.assertEqual(scanned_hosts[0].last_scan_date, '2020-11-03T21:47:56Z')
            self.assertEqual(len(scanned_hosts), 34)
            self.assertEqual(
                set(['192.168.0.103', '192.168.0.40', '192.168.0.7', '192.168.0.37', '192.168.0.39', '192.168.0.51',
                 '192.168.0.102', '192.168.0.32', '192.168.0.27', '192.168.0.45', '192.168.0.28', '192.168.0.31',
                 '192.168.0.49', '192.168.0.36', '192.168.0.46', '192.168.0.35', '192.168.0.101', '192.168.0.9',
                 '192.168.0.13', '192.168.0.5', '192.168.0.42', '192.168.0.25', '192.168.0.6', '192.168.0.2',
                 '192.168.0.10', '192.168.0.14', '192.168.0.3', '192.168.0.15', '192.168.0.30', '192.168.0.38',
                 '192.168.0.8', '192.168.0.23', '192.168.0.50', '192.168.0.26']),
                set([x.ip_address for x in scanned_hosts]))
            self.assertEqual(len(vulns), 155)

            vuln = vulns['798d53cb-4479-3010-b6ed-7bcf2e816880']
            self.assertEqual(vuln.cve.id, 'NOCVE-1.3.6.1.4.1.25623.1.0.900600')
            self.assertEqual(vuln.cve.base_score_v2, 6.4)
            self.assertEqual(vuln.cve.access_vector_v2, AccessVectorV2.NETWORK)
            self.assertEqual(vuln.cve.access_complexity_v2, AccessComplexityV2.LOW)
            self.assertEqual(vuln.cve.authentication_v2, AuthenticationV2.NONE)
            self.assertEqual(vuln.cve.confidentiality_impact_v2, ImpactV2.PARTIAL)
            self.assertEqual(vuln.cve.integrity_impact_v2, ImpactV2.PARTIAL)
            self.assertEqual(vuln.cve.availability_impact_v2, ImpactV2.NONE)
            self.assertEqual(vuln.port, '21')
            self.assertEqual(vuln.protocol, 'tcp')
            self.assertEqual(vuln.scan_date, '2020-11-03T21:43:10Z')
            self.assertEqual(vuln.name, 'Anonymous FTP Login Reporting')
            self.assertEqual(vuln.solution, 'If you do not want to share files, you should disable\n                            anonymous logins.')
            self.assertEqual(vuln.scan_file_url, "report_gmp_9.xml")

            vuln = vulns['e25a7c6d-471a-3097-9701-58663d84d98e']
            self.assertEqual(vuln.cve.id, 'CVE-2003-1567')
            self.assertEqual(vuln.port, '80')
            self.assertEqual(vuln.protocol, 'tcp')
            self.assertEqual(vuln.scan_date, '2020-11-03T21:50:18Z')
            self.assertEqual(vuln.name, 'HTTP Debugging Methods (TRACE/TRACK) Enabled')
            self.assertEqual(vuln.scan_file_url, "report_gmp_9.xml")

class OpenVasClientTest(TestCase):
    fixtures = ['openvas_config.json']

    def setUp(self):
        self.config = Config.objects.first()
        self.uut = OpenVasClient(self.config)

    def test_is_instance(self):
        self.assertIsInstance(self.uut, Client)

    def test_get_targets_omp_7(self):
        target_xml = get_root_element(get_fixture_location(__file__, "target_omp_7.xml"))
        target2_xml = get_root_element(get_fixture_location(__file__, "target2_omp_7.xml"))
        target3_xml = get_root_element(get_fixture_location(__file__, "target3_omp_7.xml"))

        with open(get_fixture_location(__file__, "report_with_target_omp_7.xml"), 'r') as xml:
            with patch.object(self.uut, "_get_target_definition", return_value=target_xml) as target_def:
                target = self.uut.get_targets(xml)
                self.assertEqual(target, IPSet(IPNetwork("192.168.1.0/24")))
                target_def.assert_called_once_with("e39cf6fa-1932-42c5-89d4-b66f469c615b")

        with open(get_fixture_location(__file__, "report_with_target_omp_7.xml"), 'r') as xml:
            with patch.object(self.uut, "_get_target_definition", return_value=target2_xml) as target_def:
                ip_set = IPSet(IPRange(start="192.168.1.1", end="192.168.1.200"))
                target = self.uut.get_targets(xml)
                self.assertEqual(target, ip_set)
                target_def.assert_called_once_with("e39cf6fa-1932-42c5-89d4-b66f469c615b")

        with open(get_fixture_location(__file__, "report_with_target_omp_7.xml"), 'r') as xml:
            with patch.object(self.uut, "_get_target_definition", return_value=target3_xml) as target_def:
                ip_set = IPSet()
                ip_set.add(IPAddress("10.31.2.30"))
                ip_set.add(IPAddress("10.31.2.23"))
                ip_set.add(IPAddress("10.31.2.7"))
                ip_set.add(IPAddress("10.31.2.31"))
                ip_set.add(IPAddress("10.31.2.11"))
                ip_set.add(IPAddress("10.31.2.21"))
                ip_set.add(IPRange(start="10.31.2.34", end="10.31.2.35"))
                ip_set.add(IPAddress("10.31.2.20"))
                ip_set.add(IPAddress("10.31.2.32"))
                target = self.uut.get_targets(xml)
                self.assertEqual(target, ip_set)
                target_def.assert_called_once_with("e39cf6fa-1932-42c5-89d4-b66f469c615b")

    def test_get_targets_gmp_9(self):
        with open(get_fixture_location(__file__, "report_gmp_9.xml"), 'r') as xml:
            target_xml = get_root_element(get_fixture_location(__file__, "target_gmp_9.xml"))


            with patch.object(self.uut, "_get_target_definition", return_value=target_xml) as target_def:
                target = self.uut.get_targets(xml)
                self.assertEqual(target, IPSet(IPNetwork("192.168.0.0/24")))
                target_def.assert_called_once_with("71ffd436-52da-48c4-a39d-0ac28080c876")

