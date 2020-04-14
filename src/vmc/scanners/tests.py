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

from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.tasks import update, update_data, _update
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

    @patch('vmc.scanners.tasks.update_data')
    def test_call_update(self, update_data):
        self.client().get_scans.return_value = 'get_scans'
        self.parser().get_scans_ids.return_value = [1]

        update()

        self.client().get_scans.assert_called_once_with(last_modification_date=self.config.last_scans_pull)
        self.parser().get_scans_ids.assert_called_once_with('get_scans')
        update_data.delay.assert_called_once_with(config_pk=self.config.id, scan_id=1)

    def test_call_update_exception(self):
        self.client().get_scans.side_effect = Exception

        update()
        self.parser().get_scans_ids.assert_not_called()

    @patch('vmc.scanners.tasks._update')
    def test_update_data_call(self, _update):
        _update.return_value = True

        self.assertTrue(update_data(self.config.id, 1))
        _update.assert_called_with(self.config, 1)

    @patch('vmc.scanners.tasks._update')
    def test_update_data_memcache_lock(self, _update):
        lock_id = F'update-vulnerabilities-loc-99'
        with memcache_lock(lock_id, self.config.id):
            self.assertFalse(update_data(self.config.id, 99))
            _update.assert_not_called()

    @patch('vmc.scanners.tasks.VulnerabilityDocument')
    def test__update_call(self, document):
        self.client().download_scan.return_value = 'download_scan'
        self.parser().parse.return_value = 'first', 'second'

        self.assertTrue(_update(self.config, 1))

        self.client().download_scan.assert_called_once_with(1)
        self.parser().parse.assert_called_once_with('download_scan')
        document.create_or_update.assert_called_once_with('first', 'second', self.config)

    @patch('vmc.scanners.tasks.VulnerabilityDocument')
    def test___update_exception(self, document):
        self.client().download_scan.side_effect = Exception

        self.assertFalse(_update(self.config, 1))

        self.parser().get_scans_ids.assert_not_called()
        document.create_or_update.assert_not_called()
