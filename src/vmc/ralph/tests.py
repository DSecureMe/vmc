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
import uuid
from unittest import skipIf
from unittest.mock import patch
from parameterized import parameterized

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase

from vmc.ralph.parsers import AssetsParser, OwnerParser
from vmc.config.test_settings import elastic_configured
from vmc.assets.documents import Impact as AssetImpact, AssetDocument, OwnerInnerDoc

from vmc.common.tests import get_fixture_location
from vmc.ralph.apps import RalphConfig
from vmc.ralph.clients import RalphClient
from vmc.ralph.models import Config
from vmc.elasticsearch import Search
from vmc.elasticsearch.tests import ESTestCase

from vmc.ralph.tasks import start_update_assets, update_assets


class ResponseMock:

    def __init__(self, resp, status_code=200):
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

    def test_call__str__(self):
        self.assertEqual(self.uut.__str__(), 'Test Ralph Config')


class RalphClientTest(TestCase):
    fixtures = ['config.json']

    def setUp(self):
        self.config = Config.objects.get(pk=1)
        self.uut = RalphClient(self.config)

    @staticmethod
    def _get_response(name: str):
        with open(get_fixture_location(__file__, name)) as f:
            return json.loads(f.read())

    @patch('vmc.ralph.clients.requests')
    def test_get_auth_header_call(self, request_mock):
        request_mock.request.return_value = ResponseMock({'token': 'auth_token'})
        self.assertEqual({'Authorization': 'Token auth_token'}, self.uut.get_auth_header())
        request_mock.request.assert_called_once_with(
            'POST',
            'http://test:80/api-token-auth/',
            headers={'Content-Type': 'application/json'},
            data=json.dumps({'username': self.config.username, 'password': self.config.password}),
            verify=False
        )

    @patch('vmc.ralph.clients.requests')
    def test_get_auth_header_call_token_exists(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.assert_not_called()
        self.assertEqual({'Authorization': 'Token auth_token'}, self.uut.get_auth_header())

    @patch('vmc.ralph.clients.requests')
    def test_get_assets_call(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.return_value = ResponseMock(self._get_response('all_hosts_response.json'))

        result = self.uut.get_assets()
        self.assertIs(type(result), list)
        self.assertIs(type(result[0]), dict)
        self.assertEqual(len(result), 1)
        request_mock.request.assert_called_once_with(
            'GET',
            'http://test:80/api/data-center-assets/?format=json&limit=500',
            headers={'Authorization': 'Token auth_token'},
            verify=False
        )

    @patch('vmc.ralph.clients.requests')
    def test_get_users_call(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.return_value = ResponseMock(self._get_response('all_users.json'))

        result = self.uut.get_users()
        self.assertIs(type(result), list)
        self.assertIs(type(result[0]), dict)
        self.assertEqual(len(result), 1)
        request_mock.request.assert_called_once_with(
            'GET',
            'http://test:80/api/users/?format=json&limit=500',
            headers={'Authorization': 'Token auth_token'},
            verify=False
        )


class OwnerParserTest(TestCase):

    def setUp(self) -> None:
        self.uut = OwnerParser
        with open(get_fixture_location(__file__, 'users_response.json')) as f:
            self.users = json.loads(f.read())

    def test_call_parse(self):
        result = self.uut.parse(self.users)
        self.assertEqual(len(result), 1)
        self.assertEqual(type(result), dict)
        self.assertEqual(type(result[1]), OwnerInnerDoc)
        self.assertEqual(result[1].name, 'M W (DS)')
        self.assertEqual(result[1].email, 'contact@dsecure.me')
        self.assertEqual(result[1].department, 'DEPARTMENT')
        self.assertEqual(result[1].team, 'TEAM')


class AssetsParserTest(TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        self.config = Config.objects.first()
        self.uut = AssetsParser(self.config)
        self.asset_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '1-102-10.0.0.25'))
        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            self.hosts = [json.loads(f.read())]

    def assert_fields(self, result):
        self.assertEqual(len(result), 2)
        self.assertEqual(result[self.asset_id].tags, [self.config.name])
        self.assertEqual(result[self.asset_id].id, self.asset_id)
        self.assertEqual(result[self.asset_id].ip_address, '10.0.0.25')
        self.assertEqual(result[self.asset_id].mac_address, '02:44:AA:BB:77:99')
        self.assertEqual(result[self.asset_id].confidentiality_requirement, AssetImpact.HIGH)
        self.assertIsInstance(result[self.asset_id].confidentiality_requirement, AssetImpact)
        self.assertEqual(result[self.asset_id].integrity_requirement, AssetImpact.NOT_DEFINED)
        self.assertIsInstance(result[self.asset_id].integrity_requirement, AssetImpact)
        self.assertEqual(result[self.asset_id].availability_requirement, AssetImpact.NOT_DEFINED)
        self.assertIsInstance(result[self.asset_id].availability_requirement, AssetImpact)
        self.assertEqual(result[self.asset_id].os, 'Windows Server 2003')
        self.assertEqual(result[self.asset_id].hostname, 'ralph1.allegro.pl')
        self.assertEqual(result[self.asset_id].url, 'http://test:80/data_center/datacenterasset/62')

    def test_parse_called(self):
        result = self.uut.parse(self.hosts)
        self.assert_fields(result)
        self.assertEqual(result[self.asset_id].business_owner, [{}])
        self.assertEqual(result[self.asset_id].technical_owner, [{}])

    def test_parse_with_users_called(self):
        users = {35: OwnerInnerDoc(name='FNAME LNAME (FLBO)', email='contact@dsecure.me')}
        result = self.uut.parse(self.hosts, users)
        self.assert_fields(result)
        self.assertEqual(result[self.asset_id].business_owner, [{'name': 'FNAME LNAME (FLBO)', 'email': 'contact@dsecure.me'}])
        self.assertEqual(result[self.asset_id].technical_owner, [{'name': 'FNAME LNAME (FLBO)', 'email': 'contact@dsecure.me'}])


class UpdateAssetsTaskTest(TestCase):
    fixtures = ['config.json']
    RESPONSE = [1, 2]
    USERS = [1, 2]

    def setUp(self) -> None:
        super().setUp()
        self.config = Config.objects.first()

    @patch('vmc.ralph.tasks.update_assets')
    def test_start_update_assets_call(self, update_assets_mock):
        start_update_assets()
        update_assets_mock.delay.assert_called_once_with(config_id=self.config.id)

    @patch('vmc.ralph.tasks.RalphClient')
    @patch('vmc.ralph.tasks.OwnerParser')
    @patch('vmc.ralph.tasks.AssetsParser')
    @patch('vmc.ralph.tasks.AssetDocument')
    def test_update_assets_call(self, asset_document_mock, asset_parser, owner_parser, mock_api):
        mock_api().get_assets.return_value = self.RESPONSE
        mock_api().get_users.return_value = self.USERS
        asset_parser().parse.return_value = self.RESPONSE
        owner_parser.parse.return_value = self.USERS

        update_assets(self.config.id)

        mock_api.assert_called_with(self.config)
        mock_api().get_users.assert_called_once()
        owner_parser.parse.assert_called_with(self.USERS)
        mock_api().get_assets.assert_called_once()
        asset_parser.assert_called_with(self.config)
        asset_parser().parse.assert_called_with(self.USERS, self.RESPONSE)
        asset_document_mock.create_or_update.assert_called_once_with(self.RESPONSE, self.config)

    @patch('vmc.ralph.tasks.RalphClient')
    @patch('vmc.ralph.tasks.AssetsParser')
    def test_update_assets_call_exception(self, factory_mock, mock_api):
        mock_api().get_assets.side_effect = Exception('Unknown')
        update_assets(self.config.id)
        factory_mock.parse.assert_not_called()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateAssetsIntegrationTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        super().setUp()
        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            self.hosts = [json.loads(f.read())]
        with open(get_fixture_location(__file__, 'users_response.json')) as f:
            self.users = json.loads(f.read())
        self.config_id = Config.objects.first().id

    def update_assets(self, mock_api):
        mock_api().get_assets.return_value = self.hosts
        mock_api().get_users.return_value = self.users

        update_assets(self.config_id)
        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.23').count(), 1)
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.25').count(), 1)

        update_assets(self.config_id)
        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())

    @patch('vmc.ralph.tasks.RalphClient')
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
