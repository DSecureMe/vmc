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

from unittest.mock import patch, MagicMock, call

from django.test import TestCase

from vmc.assets.models import Asset, Port
from vmc.nessus.api import Nessus
from vmc.nessus.models import Config
from vmc.nessus.tasks import get_trash_folder_id, cleanup_assets, update, update_data
from vmc.vulnerabilities.models import Vulnerability

from src.vmc.common.tests import get_fixture_location


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


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


class CleanupAssetsTest(TestCase):
    fixtures = ['assets.json']

    def test_call_cleanup_assets(self):
        self.assertEqual(Asset.objects.count(), 2)
        self.assertEqual(Port.objects.count(), 1)
        cleanup_assets()
        self.assertEqual(Asset.objects.count(), 0)
        self.assertEqual(Port.objects.count(), 0)
        self.assertEqual(Vulnerability.objects.count(), 0)

    def test_call_twice(self):
        cleanup_assets()
        cleanup_assets()
        self.assertEqual(Asset.objects.count(), 0)


class UpdateTest(TestCase):
    fixtures = ['assets.json', 'config.json']

    def setUp(self):
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
        self.assertEqual(Asset.objects.count(), 0)
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


class UpdateDataTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
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

        vuln = Vulnerability.objects.filter(asset__ip_address='10.0.2.15').first()
        self.assertEqual(vuln.asset.ip_address, '10.0.2.15')
        self.assertEqual(vuln.asset.os, 'Linux Kernel 3.10.0-957.5.1.el7.x86_64 on CentOS Linux release 7.6.1810 (Core)')
        self.assertEqual(vuln.port.number, 22)
        self.assertEqual(vuln.port.svc_name, 'ssh')
        self.assertEqual(vuln.port.protocol, 'tcp')
        self.assertEqual(vuln.cve.id, 'CVE-2008-5161')
        self.assertEqual(vuln.solution, 'Contact the vendor or consult product documentation to disable CBC mode '
                                        'cipher encryption, and enable CTR or GCM cipher mode encryption.')
        self.assertFalse(vuln.exploit_available)
