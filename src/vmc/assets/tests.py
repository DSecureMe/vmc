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
from unittest import skipIf

from django.test import TestCase
from parameterized import parameterized

from vmc.common.elastic.tests import ESTestCase
from vmc.assets.apps import AssetsConfig

from vmc.assets.documents import AssetDocument, Impact

from vmc.config.test_settings import elastic_configured


class AssetsConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(AssetsConfig.name, 'vmc.assets')


class ImpactTest(TestCase):

    @parameterized.expand([
        (Impact.LOW, 0.5),
        (Impact.MEDIUM, 1.0),
        (Impact.HIGH, 1.51),
        (Impact.NOT_DEFINED, 1.0)
    ])
    def test_values(self, first, second):
        self.assertEqual(first.second_value, second)

    @parameterized.expand([
        (Impact.LOW, 'LOW'),
        (Impact.MEDIUM, 'MEDIUM'),
        (Impact.HIGH, 'HIGH'),
        (Impact.NOT_DEFINED, 'NOT_DEFINED')
    ])
    def test_values_str(self, first, second):
        self.assertEqual(first.name, second)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class AssetDocumentTest(ESTestCase, TestCase):

    def test_document_index_name(self):
        self.assertEqual(AssetDocument.Index.name, 'asset')

    def test_document(self):
        AssetDocument(
            ip_address='10.10.10.1',
            os='Windows',
            cmdb_id='1',
            confidentiality_requirement='NOT_DEFINED',
            integrity_requirement='NOT_DEFINED',
            availability_requirement='NOT_DEFINED',
            business_owner='test-business_owner',
            technical_owner='test-technical_owner',
            hostname='test-hostname',
            change_reason='create'
        ).save(refresh=True)

        result = AssetDocument.search().filter('term', ip_address='10.10.10.1').execute()
        self.assertEqual(len(result.hits), 1)

        uut = result.hits[0]
        self.assertEqual(uut.os, 'Windows')
        self.assertEqual(uut.confidentiality_requirement.name, Impact.NOT_DEFINED.name)
        self.assertEqual(uut.integrity_requirement.name, Impact.NOT_DEFINED.name)
        self.assertEqual(uut.availability_requirement.name, Impact.NOT_DEFINED.name)
        self.assertEqual(uut.confidentiality_requirement.second_value, Impact.NOT_DEFINED.second_value)
        self.assertEqual(uut.integrity_requirement.second_value, Impact.NOT_DEFINED.second_value)
        self.assertEqual(uut.availability_requirement.second_value, Impact.NOT_DEFINED.second_value)
        self.assertEqual(uut.business_owner, 'test-business_owner')
        self.assertEqual(uut.technical_owner, 'test-technical_owner')
        self.assertEqual(uut.hostname, 'test-hostname')
        self.assertEqual(uut.change_reason, 'create')
        self.assertTrue(uut.created_date)
        self.assertTrue(uut.modified_date)
