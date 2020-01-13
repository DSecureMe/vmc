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
from unittest.mock import patch, MagicMock, call

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase
from elasticsearch_dsl import Search

from vmc.common.elastic.tests import ESTestCase
from vmc.config.test_settings import elastic_configured
from vmc.nessus.apps import NessusConfig

from vmc.assets.documents import AssetDocument
from vmc.nessus.api import Nessus
from vmc.nessus.models import Config
from vmc.nessus.tasks import get_trash_folder_id, update, update_data
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.common.tests import get_fixture_location


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


class NessusConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(NessusConfig.name, 'vmc.nessus')


class NessusTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
        self.config = Config.objects.get(pk=1)
        self.uut = Nessus(self.config)
        self.headers = {
            'X-ApiKeys': 'accessKey={};secretKey={}'.format(self.config.api_key, self.config.secret_key),
            'Content-type': 'application/json',
            'Accept': 'text/plain'
        }

    def assert_request(self, request_mock, method, action):
        request_mock.request.assert_called_with(
            method,
            'http://test/{}'.format(action),
            data='{}',
            headers=self.headers,
            verify=not self.config.insecure
        )

    @patch('vmc.nessus.api.requests')
    def test_call_get_scan_list(self, request_mock):
        request_mock.request.return_value = ResponseMock({'scan': 1}, 200)

        scan_list = self.uut.get_scan_list()
        self.assert_request(request_mock, 'GET', 'scans')
        self.assertEqual(scan_list, {'scan': 1})

    @patch('vmc.nessus.api.requests')
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


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateDataTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self):
        super().setUp()
        self.con = MagicMock()
        self.scanner_api = MagicMock(return_value=self.con)
        self.config_id = Config.objects.first().id

    def test_call(self):
        self.con.download_scan.return_value = open(get_fixture_location(__file__, 'internal.xml'))

        update_data(config_pk=self.config_id,
                    scan_id=1,
                    scaner_api=self.scanner_api)

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
