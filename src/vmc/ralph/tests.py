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

import json
from unittest import skipIf
from unittest.mock import patch, Mock
from parameterized import parameterized

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase
from elasticsearch_dsl import Search

from vmc.ralph.parsers import AssetsParser
from vmc.config.test_settings import elastic_configured
from vmc.assets.documents import Impact as AssetImpact, AssetDocument

from vmc.ralph.apps import RalphConfig
from vmc.ralph.api import Ralph
from vmc.ralph.models import Config
from vmc.common.tests import get_fixture_location
from vmc.common.elastic.tests import ESTestCase

from vmc.ralph.tasks import start_update_assets, update_assets


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


class RalphConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(RalphConfig.name, 'vmc.ralph')


class ModelConfigTest(TestCase):
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


class RalphTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
        self.config = Config.objects.get(pk=1)
        self.uut = Ralph(self.config)

    @patch('vmc.ralph.api.requests')
    def test_call_get_token(self, request_mock):
        request_mock.request.return_value = ResponseMock({'token': '79ee13720dbf474399dde532daad558aaeb131c3'}, 200)

        token = self.uut.get_token()
        self.assertEqual(token, '79ee13720dbf474399dde532daad558aaeb131c3')

    @patch('vmc.ralph.api.requests')
    def test_call_get_host_by_id(self, request_mock):

        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            j = f.read()
        api_response = json.loads(j)
        api_response_json = json.dumps(json.loads(j))

        self.uut.get_token = Mock(return_value='79ee13720dbf474399dde532daad558aaeb131c3')
        request_mock.request.return_value = ResponseMock(json.dumps(api_response), 200)
        result = self.uut.get_host_data_by_id(62)

        self.assertEqual(result, api_response_json)

    @patch('vmc.ralph.api.requests')
    def test_call_no_such_host_exception(self, request_mock):

        self.uut.get_token = Mock(return_value='79ee13720dbf474399dde532daad558aaeb131c3')
        request_mock.request.return_value = ResponseMock('{"detail":"Not found."}', 200)

        result = self.uut.get_host_data_by_id('a')
        self.assertEqual(result, 'Such asset doesn\'t exist')

    @patch('vmc.ralph.api.requests')
    def test_call_get_all_assets(self, request_mock):

        self.uut.get_token = Mock(return_value='79ee13720dbf474399dde532daad558aaeb131c3')

        with open(get_fixture_location(__file__, 'all_hosts_response.json')) as f:
            j = f.read()
        api_response = j
        request_mock.request.return_value = ResponseMock(api_response, 200)
        result = self.uut.get_all_assets()
        self.assertIs(type(result), list)
        self.assertIs(type(result[0]), dict)
        self.assertEqual(len(result), 1)


class AssetsParserTest(TestCase):
    CONFIG_NAME = 'test_name'

    def setUp(self) -> None:
        self.uut = AssetsParser(AssetsParserTest.CONFIG_NAME)
        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            self.hosts = [json.loads(f.read())]

    def test_parse_called(self):
        result = self.uut.parse(self.hosts)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].tags, [AssetsParserTest.CONFIG_NAME])
        self.assertEqual(result[0].cmdb_id, 62)
        self.assertEqual(result[0].ip_address, '10.0.0.25')
        self.assertEqual(result[0].mac_address, '02:44:AA:BB:77:99')
        self.assertEqual(result[0].confidentiality_requirement, AssetImpact.HIGH)
        self.assertEqual(result[0].integrity_requirement, AssetImpact.NOT_DEFINED)
        self.assertEqual(result[0].availability_requirement, AssetImpact.NOT_DEFINED)
        self.assertEqual(result[0].os, 'Windows Server 2003')
        self.assertEqual(result[0].hostname, 'ralph1.allegro.pl')
        self.assertEqual(result[0].business_owner, 'FNAME LNAME (FLBO)')
        self.assertEqual(result[0].technical_owner, 'FNAME LNAME (FLTO)')


class UpdateAssetsTaskTest(TestCase):
    fixtures = ['config.json']
    RESPONSE = [1, 2]

    def setUp(self) -> None:
        super().setUp()
        self.config = Config.objects.first()

    @patch('vmc.ralph.tasks.update_assets')
    def test_start_update_assets_call(self, update_assets_mock):
        start_update_assets()
        update_assets_mock.delay.assert_called_once_with(config_id=self.config.id)

    @patch('vmc.ralph.tasks.Ralph')
    @patch('vmc.ralph.tasks.AssetsParser')
    @patch('vmc.ralph.tasks.AssetDocument')
    def test_update_assets_call(self, asset_document_mock, parser_mock, mock_api):
        mock_api().get_all_assets.return_value = self.RESPONSE
        parser_mock().parse.return_value = self.RESPONSE

        update_assets(self.config.id)

        mock_api.assert_called_with(self.config)
        parser_mock.assert_called_with(self.config.name)
        parser_mock().parse.assert_called_with(self.RESPONSE)
        asset_document_mock.create_or_update.assert_called_once_with(self.RESPONSE)

    @patch('vmc.ralph.tasks.Ralph')
    @patch('vmc.ralph.tasks.AssetsParser')
    def test_update_assets_call_exception(self, factory_mock, mock_api):
        mock_api().get_all_assets.side_effect = Exception('Unknown')
        update_assets(self.config.id)
        factory_mock.parse.assert_not_called()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateAssetsIntegrationTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        super().setUp()
        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            self.hosts = [json.loads(f.read())]
        self.config_id = Config.objects.first().id

    def update_assets(self, mock_api):
        mock_api().get_all_assets.return_value = self.hosts
        update_assets(self.config_id)
        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.23').count(), 1)
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.25').count(), 1)

    @patch('vmc.ralph.tasks.Ralph')
    def test_call(self, mock_api):
        self.update_assets(mock_api)
        self.update_assets(mock_api)


class AdminPanelTest(LiveServerTestCase):
    fixtures = ['users.json', 'config.json']

    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.get(username='admin'))

    def test_button_exists(self):
        self.assertContains(self.client.get('/admin/ralph/config/'), 'ralph-import')

    @patch('vmc.ralph.admin.start_update_assets')
    def test_call_update_cve(self, load_all_assets):
        response = self.client.get('/admin/ralph/config/import', follow=True)
        load_all_assets.delay.assert_called_once()
        self.assertContains(response, 'Importing started.')

    def tearDown(self):
        self.client.logout()
