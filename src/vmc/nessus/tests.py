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
from unittest import skipIf, mock
from unittest.mock import patch, MagicMock, call

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase
from vmc.nessus.parsers import NessusReportParser

from vmc.config.test_settings import elastic_configured
from vmc.elasticsearch import Search
from vmc.elasticsearch.tests import ESTestCase
from vmc.nessus.apps import NessusConfig

from vmc.assets.documents import AssetDocument
from vmc.nessus.clients import NessusClient
from vmc.nessus.models import Config
from vmc.nessus.tasks import get_trash_folder_id, update, update_data, get_epoch_from_lsp
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.common.tests import get_fixture_location


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


class ConfigMock:
    def __init__(self):
        self.name = 'test'
        self.tenant = None


class NessusConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(NessusConfig.name, 'vmc.nessus')


class NessusTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
        self.config = Config.objects.get(pk=1)
        self.uut = NessusClient(self.config)
        self.headers = {
            'X-ApiKeys': F'accessKey={self.config.api_key};secretKey={self.config.secret_key}',
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

    @patch('vmc.nessus.clients.requests')
    def test_call_get_scan_list(self, request_mock):
        request_mock.request.return_value = ResponseMock({'scan': 1}, 200)

        scan_list = self.uut.get_scan_list()
        self.assert_request(request_mock, 'GET', 'scans')
        self.assertEqual(scan_list, {'scan': 1})

        scan_list2 = self.uut.get_scan_list(last_modification_date=1551398400)
        self.assert_request(request_mock, 'GET', 'scans?last_modification_date=1551398400')
        self.assertEqual(scan_list2, {'scan': 1})

    @patch('vmc.nessus.clients.requests')
    def test_call_get_scan_detail(self, request_mock):
        request_mock.request.return_value = ResponseMock({'foo': 1}, 200)

        resp = self.uut.get_scan_detail(1)
        self.assert_request(request_mock, 'GET', 'scans/1')

        self.assertEqual(resp, {'foo': 1})


class GetTrashFolderIdTest(TestCase):

    def test_call_return_None(self):
        self.assertIsNone(get_trash_folder_id({}))

    def test_call(self):
        self.assertEqual(get_trash_folder_id({'folders': [{'type': 'trash', 'id': 1}]}), 1)

    def test_call_no_trash(self):
        self.assertIsNone(get_trash_folder_id({'folders': [{'type': 'foo', 'id': 2}]}))


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self):
        super().setUp()
        self.con = MagicMock()
        self.scanner_api = MagicMock(return_value=self.con)

    @patch('vmc.nessus.tasks.update_data')
    def test_call_only_trash(self, update_data_mock):
        self.con.get_scan_list.return_value = {
            'folders': [
                {
                    'type': 'trash',
                    'id': 1,
                },
            ],
            'scans': [
                {
                    'folder_id': 1
                }
            ]}

        update(scanner_api=self.scanner_api)
        self.assertEqual(Search().index(AssetDocument.Index.name).count(), 0)
        self.scanner_api.assert_called_once_with(Config.objects.first())
        update_data_mock.delay.assert_not_called()

    @patch('vmc.nessus.tasks.update_data')
    def test_call(self, update_data_mock):
        self.con.get_scan_list.return_value = {
            'scans': [
                {'folder_id': 1, 'name': 'SCAN 1', 'id': 2},
                {'folder_id': 3, 'name': 'SCAN 2', 'id': 4}

            ]
        }

        update(scanner_api=self.scanner_api)
        update_data_mock.delay.assert_has_calls([
            call(config_pk=1, scan_id=2),
            call(config_pk=1, scan_id=4)
        ], any_order=True)

    def test_call_lsp_update(self):
        with mock.patch('vmc.nessus.tasks.now') as mock_now:
            mock_now.return_value = datetime.datetime(2020, 3, 21, 0, 0, 0, tzinfo=datetime.timezone.utc)
            self.assertEquals(Config.objects.first().last_scans_pull, datetime.datetime(2019, 3, 1, 0, 0, 0,
                                                                                        tzinfo=datetime.timezone.utc))
            update(scanner_api=self.scanner_api)
            self.scanner_api.assert_called_once_with(Config.objects.first())
            self.assertEquals(Config.objects.first().last_scans_pull, datetime.datetime(2020, 3, 21, 0, 0, 0,
                                                                                        tzinfo=datetime.timezone.utc))


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class ReportParserTest(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        self.internal_xml = open(get_fixture_location(__file__, 'internal.xml'))
        self.uut = NessusReportParser(ConfigMock())

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


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateDataTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self):
        super().setUp()
        self.con = MagicMock()
        self.scanner_api = MagicMock(return_value=self.con)
        self.config = Config.objects.first()
        self.config_id = Config.objects.first().id

    def test_call(self):
        self.con.download_scan.return_value = open(get_fixture_location(__file__, 'internal.xml'))

        update_data(config_pk=self.config_id,
                    scan_id=1,
                    scanner_api=self.scanner_api)

        self.scanner_api.assert_called_once_with(Config.objects.get(pk=1))
        self.con.download_scan.assert_called_once_with(1)


        vuln = VulnerabilityDocument.search().filter('term', asset__ip_address='10.0.2.15').execute()
        self.assertEqual(len(vuln.hits), 1)
        self.assertEqual(vuln.hits[0].asset.ip_address, '10.0.2.15')
        self.assertEqual(vuln.hits[0].port, 22)
        self.assertEqual(vuln.hits[0].svc_name, 'ssh')
        self.assertEqual(vuln.hits[0].protocol, 'tcp')
        self.assertEqual(vuln.hits[0].cve.id, 'CVE-2008-5161')
        self.assertEqual(vuln.hits[0].solution, 'Contact the vendor or consult product documentation to disable CBC mode '
                                        'cipher encryption, and enable CTR or GCM cipher mode encryption.')

    def test_get_epoch_from_lsp(self):
        c = Config.objects.get(pk=1)
        self.assertEqual(get_epoch_from_lsp(c.last_scans_pull), 1551398400)
        c.last_scans_pull = None
        self.assertEqual(get_epoch_from_lsp(c.last_scans_pull), 0)


class AdminPanelTest(LiveServerTestCase):
    fixtures = ['users.json', 'config.json']

    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.get(username='admin'))

    def test_button_exists(self):
        self.assertContains(self.client.get('/admin/nessus/config/'), 'nessus-import')

    @patch('vmc.nessus.admin.update')
    def test_call_update_cve(self, update):
        response = self.client.get('/admin/nessus/config/import', follow=True)
        update.delay.assert_called_once()
        self.assertContains(response, 'Importing started.')

    def tearDown(self):
        self.client.logout()
