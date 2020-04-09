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

import defusedxml.ElementTree as ET

from django.test import TestCase


from vmc.config.test_settings import elastic_configured
from vmc.common.tests import get_fixture_location
from vmc.elasticsearch.tests import ESTestCase

from vmc.open_vas.apps import OpenVasConfig
from vmc.open_vas.parsers import GmpResultParser


class ConfigMock:
    name = 'test'
    tenant = None


class OpenVasConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(OpenVasConfig.name, 'vmc.open_vas')


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class GmpResultParserTest(ESTestCase, TestCase):

    def test_get_reports_ids_call(self):
        xml = ET.parse(get_fixture_location(__file__, 'reports.xml'))
        ids = GmpResultParser.get_reports_ids(xml)
        self.assertEquals(ids, ['0f9ea6ca-→abf5-4139-a772-cb68937cdfbb'])

    def test_parse(self):
        xml = ET.parse(get_fixture_location(__file__, 'report.xml'))
        parser = GmpResultParser(ConfigMock)
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
