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
from elasticsearch_dsl import Search
from parameterized import parameterized

from vmc.elasticsearch import Q
from vmc.elasticsearch.tests import ESTestCase
from vmc.assets.apps import AssetsConfig

from vmc.assets.documents import AssetDocument, OwnerInnerDoc, Impact

from vmc.config.test_settings import elastic_configured


class AssetConfigMock:
    def __init__(self, name):
        self.name = name
        self.tenant = None


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

    def setUp(self):
        super().setUp()
        self.to = OwnerInnerDoc(name='to_name', email='to_nam@dsecure.me', department='department', team=['team'])
        self.bo = OwnerInnerDoc(name='bo_name', email='bo_name@dsecure.me', department='department', team=['team'])

    def test_document_index_name(self):
        self.assertEqual(AssetDocument.Index.name, 'asset')

    def create_asset(self, ip_address, tags, asset_id=1, hostname='test-hostname'):
        asset = AssetDocument(
            ip_address=ip_address,
            os='Windows',
            id=asset_id,
            confidentiality_requirement='NOT_DEFINED',
            integrity_requirement='NOT_DEFINED',
            availability_requirement='NOT_DEFINED',
            hostname=hostname,
            tags=tags
        )
        asset.technical_owner.append(self.to)
        asset.business_owner.append(self.bo)
        return asset.save(refresh=True)

    def test_document(self):
        self.create_asset(ip_address='10.10.10.1', tags=[])

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
        self.assertEqual(uut.business_owner, [{
            'name': 'bo_name', 'email': 'bo_name@dsecure.me', 'department': 'department', 'team': ['team']}])
        self.assertEqual(uut.technical_owner, [{
            'name': 'to_name', 'email': 'to_nam@dsecure.me', 'department': 'department', 'team': ['team']}])
        self.assertEqual(uut.hostname, 'test-hostname')
        self.assertTrue(uut.created_date)
        self.assertTrue(uut.modified_date)

    def test_tags(self):
        a_1_tag_1 = self.create_asset(asset_id=1, ip_address='10.0.0.1', tags=['TAG1', 'OTHER'], hostname='hostname_1')
        self.create_asset(asset_id=2, ip_address='10.0.0.2', tags=['TAG1', 'OTHER'], hostname='hostname_2')
        self.create_asset(asset_id=1, ip_address='10.0.0.1', tags=['TAG2'], hostname='hostname_1')
        self.create_asset(asset_id=2, ip_address='10.0.0.2', tags=['TAG2'], hostname='hostname_2')

        self.assertEqual(4, Search().index(AssetDocument.Index.name).count())

        a_1_tag_1_copy = a_1_tag_1.clone()
        a_1_tag_1_copy.hostname = 'hostname_1_copy'
        AssetDocument.create_or_update({a_1_tag_1_copy.id: a_1_tag_1_copy}, AssetConfigMock('TAG1'))
        self.assertEqual(4, Search().index(AssetDocument.Index.name).count())

        result = AssetDocument.search().filter(
            Q('term', ip_address=a_1_tag_1_copy.ip_address) &
            Q('term', id=a_1_tag_1_copy.id) &
            Q('match', tags='TAG1')
        ).sort('-modified_date')[0].execute()
        self.assertEqual(result.hits[0].hostname, a_1_tag_1_copy.hostname)

    def test_delete_asset(self):
        asset_1 = self.create_asset(asset_id=1, ip_address='10.0.0.1', tags=['TAG1'], hostname='hostname_1')
        asset_2 = self.create_asset(asset_id=2, ip_address='10.0.0.2', tags=['TAG1'], hostname='hostname_2')
        self.create_asset(asset_id=1, ip_address='10.0.0.1', tags=['TAG2'], hostname='hostname_1')
        self.create_asset(asset_id=2, ip_address='10.0.0.2', tags=['TAG2'], hostname='hostname_2')

        self.assertEqual(4, Search().index(AssetDocument.Index.name).count())
        AssetDocument.create_or_update({asset_1.id: asset_1}, AssetConfigMock('TAG1'))

        result = AssetDocument.search().filter(Q('match', tags='DELETED')).execute()
        self.assertEqual(1, len(result.hits))
        self.assertEqual(result.hits[0].ip_address, asset_2.ip_address)
        self.assertEqual(result.hits[0].id, asset_2.id)
