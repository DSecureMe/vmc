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
from datetime import datetime
from unittest import skipIf
from unittest.mock import patch, MagicMock, call

from django.core.cache import cache
from django.urls import reverse
from parameterized import parameterized

from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from vmc.ralph.parsers import AssetsParser, OwnerParser
from vmc.config.test_settings import elastic_configured
from vmc.assets.documents import Impact as AssetImpact, AssetDocument, OwnerInnerDoc

from vmc.common.tests import get_fixture_location
from vmc.common.tasks import workflow_in_progress, ALL_TENANTS_KEY
from vmc.ralph.apps import RalphConfig
from vmc.ralph.clients import RalphClient, RalphClientException
from vmc.ralph.models import Config
from vmc.elasticsearch import Search
from vmc.elasticsearch.models import Tenant, Config as Prefix
from vmc.elasticsearch.tests import ESTestCase

from vmc.ralph.tasks import _update_assets


class ResponseMock:

    def __init__(self, resp, status_code=200):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text

    def content(self):
        return self.text


class RalphConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(RalphConfig.name, 'vmc.ralph')


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class ModelConfigTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        super().setUp()
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

    def test_add_config_not_ok(self):
        with self.assertRaises(ValidationError, msg='Only one Ralph can be assigned to one Tenant'):
            Config.objects.create(name='test1', host='test1', username='test1', password='test1', port=80)  #nosec

    @staticmethod
    def test_add_config():
        prefix = Prefix.objects.create(name='test1', prefix='test1')
        tenant = Tenant.objects.create(name='test1', slug_name='test1', elasticsearch_config=prefix)
        Config.objects.create(name='test1', host='test1',
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
            verify=False,
            timeout=360
        )

    @patch('vmc.ralph.clients.requests')
    def test_get_auth_header_call_token_exists(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.assert_not_called()
        self.assertEqual({'Authorization': 'Token auth_token'}, self.uut.get_auth_header())

    @patch('vmc.ralph.clients.requests')
    def test_get_assets_call(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.return_value = ResponseMock(self._get_response('all_data_center_assets.json'))

        result = self.uut.get_data_center_assets()
        self.assertIs(type(result), list)
        self.assertIs(type(result[0]), dict)
        self.assertEqual(len(result), 1)
        request_mock.request.assert_called_once_with(
            'GET',
            'http://test:80/api/data-center-assets/?format=json&limit=500',
            headers={'Authorization': 'Token auth_token'},
            verify=False,
            timeout=360
        )


    @patch('vmc.ralph.clients.requests')
    def test_get_virtual_assets_call(self, request_mock):
        self.uut._api_token = 'auth_token'
        request_mock.request.return_value = ResponseMock(self._get_response('all_virtual_servers.json'))

        result = self.uut.get_virtual_assets()
        self.assertIs(type(result), list)
        self.assertIs(type(result[0]), dict)
        self.assertEqual(len(result), 1)
        request_mock.request.assert_called_once_with(
            'GET',
            'http://test:80/api/virtual-servers/?format=json&limit=500',
            headers={'Authorization': 'Token auth_token'},
            verify=False,
            timeout=360
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
            verify=False,
            timeout=360
        )

    @patch('vmc.ralph.clients.requests')
    def test_auth_exception(self, requests):
        requests.request.return_value = ResponseMock('auth error', 400)
        with self.assertRaises(RalphClientException):
            self.uut.get_auth_header()

    @patch('vmc.ralph.clients.requests')
    def test_ssl_exception(self, requests):
        requests.request.side_effect = Exception()
        with self.assertRaises(RalphClientException):
            self.uut.get_auth_header()


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

    def test_call_parse_invalid_users_list(self):
        result = self.uut.parse(['foo', 'boo'])
        self.assertEqual(result, {})


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
        self.assertEqual(set(result[self.asset_id].tags), set(["DMZ", "BOO", "FOO"]))
        self.assertEqual(result[self.asset_id].source, 'Ralph')
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
        self.assertEqual(result[self.asset_id].hostname, 'testhostname2')
        self.assertEqual(result[self.asset_id].url, 'http://test:80/data_center/datacenterasset/62')
        self.assertEqual(result[self.asset_id].service, 'load_balancing')
        self.assertEqual(result[self.asset_id].environment, 'dev')

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

    def test_parse_called_for_vurtual_servers(self):
        with open(get_fixture_location(__file__, 'virtual_host_response.json')) as f:
            self.hosts = [json.loads(f.read())]
            result = self.uut.parse(self.hosts)
            self.assert_fields(result)
            self.assertEqual(result[self.asset_id].business_owner, [{}])
            self.assertEqual(result[self.asset_id].technical_owner, [{}])


class UpdateAssetsTaskTest(TestCase):
    fixtures = ['config.json']
    RESPONSE = [1, 2]
    USERS = [1, 2]

    def setUp(self) -> None:
        super().setUp()
        self.config = Config.objects.first()

    @patch('vmc.ralph.tasks.RalphClient')
    @patch('vmc.ralph.tasks.OwnerParser')
    @patch('vmc.ralph.tasks.AssetsParser')
    @patch('vmc.ralph.tasks.AssetDocument')
    def test_update_assets_call(self, asset_document_mock, asset_parser, owner_parser, mock_api):
        mock_api().get_data_center_assets.return_value = self.RESPONSE
        mock_api().get_virtual_assets.return_value = self.RESPONSE
        mock_api().get_users.return_value = self.USERS
        asset_parser().parse.return_value = self.RESPONSE
        owner_parser.parse.return_value = self.USERS

        _update_assets(self.config.id)

        mock_api.assert_called_with(self.config)
        mock_api().get_users.assert_called_once()
        owner_parser.parse.assert_called_with(self.USERS)
        mock_api().get_data_center_assets.assert_called_once()
        mock_api().get_virtual_assets.assert_called_once()
        asset_parser.assert_called_with(self.config)

        asset_parser().parse.assert_has_calls([
            call(self.USERS, self.RESPONSE),
            call(self.USERS, self.RESPONSE)
        ])
        asset_document_mock.create_or_update.assert_has_calls(
            [call(self.RESPONSE, self.config),
             call(self.RESPONSE, self.config)
        ])

    @patch('vmc.ralph.tasks.RalphClient')
    @patch('vmc.ralph.tasks.AssetsParser')
    def test_update_assets_call_exception(self, factory_mock, mock_api):
        mock_api().get_data_center_assets.side_effect = Exception
        _update_assets(self.config.id)
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
        mock_api().get_data_center_assets.return_value = self.hosts
        mock_api().get_virtual_assets.return_value = []
        mock_api().get_users.return_value = self.users

        _update_assets(self.config_id)
        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.23').count(), 1)
        self.assertEqual(AssetDocument.search().filter('term', ip_address='10.0.0.25').count(), 1)

        _update_assets(self.config_id)
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
        self.assertContains(self.client.get('/admin/ralph/config/'), 'import-all')

    @patch('vmc.common.admin.start_workflow')
    @patch('vmc.ralph.admin.get_update_assets_workflow')
    def test_call_update_cve(self, get_workflow, start):
        get_workflow.return_value = 'get_workflow'
        response = self.client.get('/admin/ralph/config/import', follow=True)

        get_workflow.assert_called_once_with(Config.objects.first())
        start.assert_called_once_with('get_workflow', Config.objects.first())

        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), '1 config was successfully run')

    @patch('vmc.common.admin.start_workflow')
    @patch('vmc.ralph.admin.get_update_assets_workflow')
    def test_call_import_selected_configs(self, get_workflow, start):
        get_workflow.return_value = 'get_workflow'

        import_selected_url = reverse('admin:ralph_config_changelist')
        response = self.client.post(import_selected_url, {
            'action': 'run_configs',
            '_selected_action': [x.pk for x in Config.objects.all()]}, follow=True)

        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), '1 config was successfully run')

        get_workflow.assert_called_once_with(Config.objects.first())
        start.assert_called_once_with('get_workflow', Config.objects.first())

    def tearDown(self):
        self.client.logout()


class WorkflowTests(TestCase):
    fixtures = ['config.json']

    def setUp(self) -> None:
        self.config = Config.objects.get(id=1)

    def test_no_workflow_in_progress(self):
        self.assertFalse(workflow_in_progress(self.config))

    def test_no_global_workflow(self):
        cache.keys = MagicMock()
        cache.keys.return_value = False

        self.assertFalse(workflow_in_progress(self.config, True))
        cache.keys.assert_called_once_with('workflow-*')

    def test_tenant_workflow_running_global_check(self):
        cache.keys = MagicMock()
        cache.keys.return_value = True

        self.assertTrue(workflow_in_progress(self.config, True))
        cache.keys.assert_called_once_with('workflow-*')

    def test_global_workflow_running(self):
        cache.add(ALL_TENANTS_KEY, True)
        self.assertTrue(workflow_in_progress(self.config))

    def tearDown(self) -> None:
        cache.clear()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class GetAssetManagerConfigTest(ESTestCase, LiveServerTestCase):
    fixtures = ['users.json', 'tenant_test.json']
    URL = reverse('get_asset_manager_config')

    def setUp(self) -> None:
        self.user = User.objects.get(pk=1)
        self.client = APIClient()
        self.config = Config.objects.get(pk=1)

    def test_auth_missing(self):
        resp = self.client.get(self.URL)
        self.assertEqual(resp.status_code, 401)

    def test_call_get_without_param(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(self.URL)
        self.assertEqual(resp.status_code, 404)

    def test_call_get_unknown_name(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?name=aaaaaaaaaaa')
        self.assertEqual(resp.status_code, 404)

    def test_call_post(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.post(F'{self.URL}?name=aaaaaaaaaaa')
        self.assertEqual(resp.status_code, 405)

    def test_call(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?name={self.config.name}')
        self.assertEqual(resp.status_code, 200)
        resp = resp.json()

        self.assertEqual(resp['name'], self.config.name)
        self.assertEqual(resp['schema'], self.config.schema)
        self.assertEqual(resp['host'], self.config.host)
        self.assertEqual(resp['port'], self.config.port)
        self.assertEqual(resp['username'], self.config.username)
        self.assertEqual(resp['password'], self.config.password)
        self.assertEqual(resp['insecure'], self.config.insecure)
        self.assertEqual(resp['enabled'], self.config.enabled)
        self.assertEqual(resp['tenant'], self.config.tenant.name)
