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

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase

from vmc.common.tasks import memcache_lock
from vmc.assets.documents import AssetStatus
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.tasks import update_scans, _update_scans
from vmc.scanners.parsers import Parser
from vmc.scanners.clients import Client


class AdminPanelTest(LiveServerTestCase):
    fixtures = ['users.json', 'config.json']

    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.get(username='admin'))

    def test_button_exists(self):
        self.assertContains(self.client.get('/admin/scanners/config/'), 'scanners-import')

    @patch('vmc.scanners.admin.update')
    def test_call_update(self, update):
        response = self.client.get('/admin/scanners/config/import', follow=True)
        update.delay.assert_called_once()
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

    @patch('vmc.scanners.tasks._update_scans')
    def test_update_scan_call(self, _update):
        _update.return_value = True

        self.assertTrue(update_scans(self.config.id))
        _update.assert_called_with(self.config)

    @patch('vmc.scanners.tasks._update_scans')
    def test_update_scan_memcache_lock(self, _update):
        lock_id = F'update-vulnerabilities-loc-{self.config.id}'
        with memcache_lock(lock_id, self.config.id):
            self.assertFalse(update_scans(self.config.id))
            _update.assert_not_called()

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

        self.assertTrue(_update_scans(self.config))

        self.client().download_scan.assert_called_once_with(1)
        self.parser().parse.assert_called_once_with('download_scan')
        asset_mock.get_assets_with_tag.assert_called_once_with(tag=AssetStatus.DISCOVERED, config=self.config)
        asset_mock.update_gone_discovered_assets.assert_called_once_with(targets='targets', scanned_hosts='second',
                                                    discovered_assets='discovered_assets', config=self.config)
        vuln_mock.create_or_update.assert_called_once_with('first', 'second', self.config)

    @patch('vmc.scanners.tasks.VulnerabilityDocument')
    def test___update_scan_exception(self, document):
        self.client().get_scans.side_effect = Exception

        self.assertFalse(_update_scans(self.config))

        document.create_or_update.assert_not_called()
