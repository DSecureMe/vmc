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
from decimal import Decimal

from unittest import TestCase
from unittest.mock import patch, Mock

from parameterized import parameterized

from vmc.common.apps import CommonConfig
from vmc.common.enum import TupleValueEnum
from vmc.common.utils import is_downloadable, get_file, handle_ranges


def get_fixture_location(module, name):
    os.chdir(os.path.dirname(module))
    return os.path.join(os.getcwd(), 'fixtures', name)


class CommonConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(CommonConfig.name, 'vmc.common')


class TupleValueEnumTest(TestCase):
    class TestEnum(TupleValueEnum):
        LOW = ('L', Decimal('0.5'))
        MEDIUM = ('M', Decimal('1.0'))
        HIGH = ('H', Decimal('1.0'))

    def test_call_choices(self):
        self.assertEqual(self.TestEnum.choices(),
                         [('L', 'LOW'), ('M', 'MEDIUM'), ('H', 'HIGH')])

    @parameterized.expand([
        (TestEnum.LOW, Decimal('0.5')),
        (TestEnum.MEDIUM, Decimal('1.0')),
        (TestEnum.HIGH, Decimal('1.0'))
    ])
    def test_call_second_value(self, first, second):
        self.assertEqual(first.second_value, second)

    @parameterized.expand([
        (TestEnum.LOW, 'L'),
        (TestEnum.MEDIUM, 'M'),
        (TestEnum.HIGH, 'H')
    ])
    def test_call_first_value(self, first, second):
        self.assertEqual(first.value, second)

    @parameterized.expand([
        ('L', TestEnum.LOW),
        ('M', TestEnum.MEDIUM),
        ('H', TestEnum.HIGH),
        ('LOW', TestEnum.LOW),
        ('MEDIUM', TestEnum.MEDIUM),
        ('HIGH', TestEnum.HIGH),
    ])
    def test_call(self, first, second):
        self.assertEqual(self.TestEnum(first), second)

    def test_attribute_missing(self):
        with self.assertRaises(AttributeError):
            self.TestEnum('A')


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

    def test_handle_ranges(self):
        s = "192.168.1.1"
        e1 = "10"
        e2 = "20.10"
        e3 = "169.1.1"
        e4 = "192.168.1.10"

        self.assertEqual(handle_ranges([s, e1]), ["192.168.1.1", "192.168.1.10"])
        self.assertEqual(handle_ranges([s, e2]), ["192.168.1.1", "192.168.20.10"])
        self.assertEqual(handle_ranges([s, e3]), ["192.168.1.1", "192.169.1.1"])
        self.assertEqual(handle_ranges([s, e4]), ["192.168.1.1", "192.168.1.10"])
        self.assertEqual(handle_ranges([s, e4]), ["192.168.1.1", "192.168.1.10"])