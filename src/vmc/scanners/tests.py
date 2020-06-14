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
 */
"""
from unittest.mock import patch, MagicMock

from datetime import datetime
from parameterized import parameterized

from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase

from vmc.assets.documents import AssetStatus
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.tasks import _update_scans
from vmc.scanners.parsers import Parser
from vmc.scanners.clients import Client
from vmc.elasticsearch.models import Tenant, Config as Prefix


class ConfigTest(TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        self.uut = Config.objects.get(id=1)

    @parameterized.expand([
        ('http', 'http://test:80'),
        ('https', 'https://test:80'),
    ])
    def test_call_url(self, schema, expected):
        self.uut.schema = schema
        self.assertEqual(self.uut.get_url(), expected)

    def test_call__str__(self):
        self.assertEqual(self.uut.__str__(), 'Test Config')

    def test_add_config_nok(self):
        with self.assertRaises(ValidationError, msg='Only one Ralph can be assigned to one Tenant'):
            Config.objects.create(name='test1', host='test1', scanner='vmc.scanners.openvas',
                                  username='test1', password='test1')  #nosec

    @staticmethod
    def test_add_config():
        prefix = Prefix.objects.create(name='test1', prefix='test1')
        tenant = Tenant.objects.create(name='test1', slug_name='test1', elasticsearch_config=prefix)
        Config.objects.create(name='test1', host='test1', scanner='vmc.scanners.openvas',
                              username='test1', password='test1', port=80, tenant=tenant)  #nosec

    @patch('vmc.common.models.now')
    def test_set_status_call_SUCCESS(self, now):
        now.return_value = datetime.now()
        self.uut.set_status(Config.Status.SUCCESS)
        self.assertEqual(self.uut.last_update_status, Config.Status.SUCCESS.value)
        self.assertEqual(self.uut.error_description, '')
        self.assertEqual(self.uut.last_success_date, now.return_value)

    @parameterized.expand([
        (Config.Status.PENDING, ),
        (Config.Status.IN_PROGRESS, ),
        (Config.Status.ERROR, ),
    ])
    def test_set_status_call(self, status):
        self.uut.set_status(status, 'desc')
        self.assertEqual(self.uut.last_update_status, status.value)
        self.assertEqual(self.uut.error_description, 'desc')
        self.assertIsNone(self.uut.last_success_date)


class AdminPanelTest(LiveServerTestCase):
    fixtures = ['users.json', 'config.json']

    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.get(username='admin'))

    def test_button_exists(self):
        self.assertContains(self.client.get('/admin/scanners/config/'), 'scanners-import')

    @patch('vmc.scanners.admin.start_update_scans')
    def test_call_update(self, mock):
        response = self.client.get('/admin/scanners/config/import', follow=True)
        mock.assert_called_once()
        self.assertContains(response, 'Importing started.')

    def tearDown(self):
        self.client.logout()


class ParserTest(TestCase):

    def test_get_scans_ids_call(self):
        with self.assertRaises(NotImplementedError):
            Parser.get_scans_ids('aa')

    def test_parse_call(self):
        with self.assertRaises(NotImplementedError):
            Parser().parse('a')


class ClientTest(TestCase):

    def setUp(self):
        self.uut = Client()

    def test_get_scans_call(self):
        with self.assertRaises(NotImplementedError):
            self.uut.get_scans('asaasd')

    def test_download_scan_call(self):
        with self.assertRaises(NotImplementedError):
            self.uut.download_scan('scan')


class TasksTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
        self.client = MagicMock()
        self.parser = MagicMock()
        self.config = Config.objects.first()
        scanners_registry.register('test-scanner', self.client, self.parser)

    @patch('vmc.scanners.tasks.VulnerabilityDocument')
    @patch('vmc.scanners.tasks.AssetDocument')
    def test__update_call(self, asset_mock, vuln_mock):
        self.client().get_scans.return_value = 'get_scans'
        self.parser().get_scans_ids.return_value = [1]
        self.client().download_scan.return_value = 'download_scan'
        self.parser().parse.return_value = 'first', 'second'
        self.parser().get_targets.return_value = 'targets'
        self.client().get_targets.return_value = 'targets'
        asset_mock.get_assets_with_tag.return_value = 'discovered_assets'

        _update_scans(self.config.pk)

        self.client().download_scan.assert_called_once_with(1)
        self.parser().parse.assert_called_once_with('download_scan')
        asset_mock.get_assets_with_tag.assert_called_once_with(tag=AssetStatus.DISCOVERED, config=self.config)
        asset_mock.update_gone_discovered_assets.assert_called_once_with(targets='targets', scanned_hosts='second',
                                                    discovered_assets='discovered_assets', config=self.config)
        vuln_mock.create_or_update.assert_called_once_with('first', 'second', self.config)

    @patch('vmc.scanners.tasks.VulnerabilityDocument')
    def test___update_scan_exception(self, document):
        self.client().get_scans.side_effect = Exception

        self.assertFalse(_update_scans(self.config.pk))

        document.create_or_update.assert_not_called()
