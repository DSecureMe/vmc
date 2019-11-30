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
import os

from unittest import TestCase
from unittest.mock import patch, Mock

from parameterized import parameterized
from vmc.common.utils import is_downloadable, get_file


def get_fixture_location(module, name):
    os.chdir(os.path.dirname(module))
    return os.path.join(os.getcwd(), 'fixtures', name)


class UtilsTest(TestCase):
    URL = 'http://example.com'

    @parameterized.expand([
        ('text', True, False),
        ('html', True, False),
        ('zip',  False, True)
    ])
    @patch('vmc.common.utils.requests')
    def test_call_is_downloadable(self, content_type, verify, result, requests):
        requests.head.return_value = Mock(headers={'Content-Type': content_type})

        self.assertEqual(is_downloadable(UtilsTest.URL, verify), result)

        requests.head.assert_called_once_with(UtilsTest.URL, allow_redirects=True, verify=verify)

    @parameterized.expand([
        ('test.zip', 'zip', True, b'ZIP is working\n'),
        ('test.txt.gz', 'gzip', False, b'GZIP is working\n')
    ])
    @patch('vmc.common.utils.requests')
    def test_call_get_file(self, filename, content_type, verify, result, requests):
        requests.head.return_value = Mock(headers={'Content-Type': content_type})

        with open(get_fixture_location(__file__, filename), mode='r+b', encoding=None) as file:
            requests.get.return_value = Mock(
                headers={'Content-Type': content_type},
                content=file.read(),
                status_code=200
            )

        self.assertEqual(get_file(UtilsTest.URL, verify).readline(), result)
        requests.get.assert_called_once_with(UtilsTest.URL, verify=verify)

    @patch('vmc.common.utils.requests')
    def test_call_get_file_json(self, requests):
        requests.head.return_value = Mock(headers={'Content-Type': 'json'})
        requests.get.return_value = Mock(
            headers={'Content-Type': 'json'},
            content='response',
            status_code=200
        )
        self.assertEqual(get_file(UtilsTest.URL), 'response')

    @patch('vmc.common.utils.requests')
    def test_call_get_file_invalid_response(self, requests):
        requests.head.return_value = Mock(headers={'Content-Type': 'text'})
        requests.get.return_value = Mock(headers={'Content-Type': 'text'}, status_code=404)
        self.assertIsNone(get_file(UtilsTest.URL))
