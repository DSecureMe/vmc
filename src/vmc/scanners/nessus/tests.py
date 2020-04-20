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
from unittest import skipIf
from unittest.mock import patch

from django.test import TestCase


from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.nessus.parsers import NessusReportParser
from vmc.scanners.nessus.apps import NessusConfig
from vmc.scanners.nessus.clients import NessusClient

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
        self.uut = NessusReportParser(self.config)

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
        vuln_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '10.0.2.15-tcp-70658'))
        self.assertEquals(len(parsed), 1)
        self.assertIsInstance(parsed[vuln_id], VulnerabilityDocument)
        self.assertEquals(parsed[vuln_id].asset.ip_address, '10.0.2.15')
        self.assertEquals(parsed[vuln_id].cve.id, 'CVE-2008-5161')
        self.assertEquals(parsed[vuln_id].port, '22')
        self.assertEquals(parsed[vuln_id].svc_name, 'ssh')
        self.assertEquals(parsed[vuln_id].protocol, 'tcp')
        self.assertEquals(parsed[vuln_id].solution, 'Contact the vendor or consult product documentation to disable CBC mode '
                                        'cipher encryption, and enable CTR or GCM cipher mode encryption.')
        self.assertEquals(parsed[vuln_id].description, 'The SSH server is configured to support Cipher Block Chaining (CBC) '
                                                 'encryption.  This may allow an attacker to recover the plaintext '
                                                 'message from the ciphertext. Note that this plugin only checks for '
                                                 'the options of the SSH server and does not check for vulnerable'
                                                 ' software versions.')
        self.assertEquals(scanned_hosts, ['10.0.2.15', '10.0.2.4', '10.0.2.3', '10.0.2.2'])