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

from unittest.mock import patch, Mock, MagicMock

from django.test import TestCase

from vmc.assets.models import Asset, Port
from vmc.ralph.api import Ralph, AssetIdException
from vmc.ralph.models import Config
import json
from vmc.common.tests import get_fixture_location

from vmc.ralph.tasks import load_all_assets


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


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


class LoadAllAssetsTest(TestCase):

    def setUp(self) -> None:
        with open(get_fixture_location(__file__, 'host_response.json')) as f:
            self.hosts = json.loads(f.read())

    @patch('vmc.ralph.tasks.Ralph')
    def test_call(self, mock_api):

        mock_api().get_all_assets.return_value = [self.hosts]
        load_all_assets()
        self.assertEqual(2, Asset.objects.count())
