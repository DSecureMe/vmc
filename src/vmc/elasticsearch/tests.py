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
from unittest import TestCase

from elasticsearch_dsl.connections import connections

from vmc.elasticsearch.apps import ElasticSearchConfig
from vmc.elasticsearch.registries import registry
from vmc.elasticsearch.models import Config


class ESTestCase(object):

    def setUp(self):
        documents = registry.get_documents()
        for index in documents:
            documents[index].init(index=index)

        super(ESTestCase, self).setUp()

    def tearDown(self):
        client = connections.get_connection()
        for index in registry.get_documents():
            client.indices.delete(index=index, ignore=404)
        super(ESTestCase, self).tearDown()


class ConfigTest(TestCase):
    NAME = 'test'
    PREFIX = 'admin'

    def test_name(self):
        self.assertEqual(ElasticSearchConfig.name, 'vmc.elasticsearch')

    @staticmethod
    def create_config():
        return Config.objects.create(
            name=ConfigTest.NAME,
            prefix=ConfigTest.PREFIX
        )

    def test_call__str__(self):
        self.assertEqual(ConfigTest.create_config().__str__(), ConfigTest.NAME)
