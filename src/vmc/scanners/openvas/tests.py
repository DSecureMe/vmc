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

from vmc.common.xml import get_root_element
from vmc.scanners.clients import Client
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.config.test_settings import elastic_configured
from vmc.common.tests import get_fixture_location
from vmc.elasticsearch.tests import ESTestCase

from vmc.scanners.openvas.apps import OpenVasConfig
from vmc.scanners.openvas.parsers import GmpParser
from vmc.scanners.openvas.clients import OpenVasClient
from netaddr import IPSet, IPNetwork, IPRange, IPAddress


class OpenVasConfigTest(TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()

    def test_name(self):
        self.assertEqual(OpenVasConfig.name, 'vmc.scanners.openvas')

    def test_registry(self):
        self.assertIsInstance(scanners_registry.get_parser(self.config), GmpParser)
        self.assertIsInstance(scanners_registry.get_client(self.config), OpenVasClient)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class GmpResultParserTest(ESTestCase, TestCase):
    fixtures = ['openvas_config.json']

    @classmethod
    def setUpTestData(cls):
        cls.config = Config.objects.first()

    def test_get_reports_ids_call(self):
        xml = ET.parse(get_fixture_location(__file__, 'reports.xml'))
        ids = GmpParser.get_scans_ids(xml)
        self.assertEquals(ids, ['0f9ea6ca-→abf5-4139-a772-cb68937cdfbb'])

    def test_parse(self):
        xml = ET.parse(get_fixture_location(__file__, 'report.xml'))
        parser = GmpParser(self.config)
        vulns, scanned_hosts = parser.parse(xml)
        self.assertEquals(
            ['10.10.10.21', '10.10.10.21', '10.10.10.23',
             '10.10.10.23', '10.10.10.30', '10.10.10.7',
             '10.10.10.20', '10.10.10.30', '10.10.10.31',
             '10.10.10.32', '10.10.10.7', '10.10.10.20',
             '10.10.10.23', '10.10.10.30', '10.10.10.31',
             '10.10.10.32', '10.10.10.7'], scanned_hosts)
        self.assertEquals(len(vulns), 17)

        vuln = vulns['d133b95a-04cc-324b-95d0-fb329f4a811f']
        self.assertEquals(vuln.port, '135')
        self.assertEquals(vuln.protocol, 'tcp')
        self.assertEquals(vuln.solution, 'Filter incoming traffic to this ports.')


class OpenVasClientTest(TestCase):
    fixtures = ['openvas_config.json']

    def setUp(self):
        self.config = Config.objects.first()
        self.uut = OpenVasClient(self.config)

    def test_is_instance(self):
        self.assertIsInstance(self.uut, Client)

    def test_get_targets(self):
        xml = get_root_element(get_fixture_location(__file__, "report_with_target.xml"))
        target_xml = get_root_element(get_fixture_location(__file__, "target.xml"))
        target2_xml = get_root_element(get_fixture_location(__file__, "target2.xml"))
        target3_xml = get_root_element(get_fixture_location(__file__, "target3.xml"))

        with patch.object(self.uut, "_get_target_definition", return_value=target_xml) as target_def:
            target = self.uut.get_targets(xml)
            self.assertEqual(target, IPSet(IPNetwork("192.168.1.0/24")))
            target_def.assert_called_once_with("e39cf6fa-1932-42c5-89d4-b66f469c615b")

        with patch.object(self.uut, "_get_target_definition", return_value=target2_xml) as target_def:
            ip_set = IPSet(IPRange(start="192.168.1.1", end="192.168.1.200"))
            target = self.uut.get_targets(xml)
            self.assertEqual(target, ip_set)
            target_def.assert_called_once_with("e39cf6fa-1932-42c5-89d4-b66f469c615b")

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
