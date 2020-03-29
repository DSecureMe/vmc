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
    def __init__(self):
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

    def create_asset(self, ip_address, asset_id=1, hostname='test-hostname'):
        asset = AssetDocument(
            ip_address=ip_address,
            os='Windows',
            id=asset_id,
            confidentiality_requirement='NOT_DEFINED',
            integrity_requirement='NOT_DEFINED',
            availability_requirement='NOT_DEFINED',
            hostname=hostname
        )
        asset.technical_owner.append(self.to)
        asset.business_owner.append(self.bo)
        return asset.save(refresh=True)

    def test_document(self):
        self.create_asset(ip_address='10.10.10.1')

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
        self.assertEqual(uut.tags, [])
        self.assertTrue(uut.modified_date)

    def test_delete_asset(self):
        asset_1 = self.create_asset(asset_id=1, ip_address='10.0.0.1', hostname='hostname_1')
        asset_2 = self.create_asset(asset_id=2, ip_address='10.0.0.2', hostname='hostname_2')

        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        AssetDocument.create_or_update({asset_1.id: asset_1}, AssetConfigMock())

        result = AssetDocument.search().filter(Q('match', tags='DELETED')).execute()
        self.assertEqual(1, len(result.hits))
        self.assertEqual(result.hits[0].ip_address, asset_2.ip_address)
        self.assertEqual(result.hits[0].id, asset_2.id)

    def test_get_or_create_call_create_new_asset(self):
        asset_1 = self.create_asset(asset_id=1, ip_address='10.0.0.1', hostname='hostname_1')
        self.create_asset(asset_id=2, ip_address='10.0.0.2', hostname='hostname_2')

        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        AssetDocument.create_or_update({asset_1.id: asset_1}, AssetConfigMock())

        asset_3 = AssetDocument.get_or_create('10.0.0.2')
        self.assertEqual(3, Search().index(AssetDocument.Index.name).count())

        result = AssetDocument.search().filter(Q('match', tags='DISCOVERED')).execute()
        self.assertEqual(1, len(result.hits))
        self.assertEqual(result.hits[0].ip_address, asset_3.ip_address)
        self.assertEqual(result.hits[0].id, asset_3.ip_address)

    def test_get_or_create_call_get_existing_asset(self):
        asset_1 = self.create_asset(asset_id=1, ip_address='10.0.0.1', hostname='hostname_1')
        self.create_asset(asset_id=2, ip_address='10.0.0.2', hostname='hostname_2')

        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())
        AssetDocument.create_or_update({asset_1.id: asset_1}, AssetConfigMock())

        asset_3 = AssetDocument.get_or_create('10.0.0.1')
        self.assertEqual(2, Search().index(AssetDocument.Index.name).count())

        self.assertEqual(asset_3.ip_address, asset_1.ip_address)
        self.assertEqual(asset_3.hostname, asset_1.hostname)
        self.assertEqual(asset_3.id, asset_1.id)
        self.assertEqual(asset_3.confidentiality_requirement, asset_1.confidentiality_requirement)
        self.assertEqual(asset_3.integrity_requirement, asset_1.integrity_requirement)
        self.assertEqual(asset_3.availability_requirement, asset_1.availability_requirement)

    def test_update_discovered_asset(self):
        asset = AssetDocument.get_or_create('10.0.0.1')
        self.assertEqual(asset.tags, ["DISCOVERED"])
        self.assertEqual(1, Search().index(AssetDocument.Index.name).count())

        asset = AssetDocument(ip_address='10.0.0.1', os='Windows', id=1, confidentiality_requirement='NOT_DEFINED',
                              integrity_requirement='NOT_DEFINED', availability_requirement='NOT_DEFINED',
                              hostname='hostname_1')

        AssetDocument.create_or_update({asset.id: asset}, AssetConfigMock())

        self.assertEqual(1, Search().index(AssetDocument.Index.name).count())

        result = AssetDocument.search().filter('term', ip_address='10.0.0.1').execute()
        uut = result.hits[0]

        self.assertEqual(uut.os, 'Windows')
        self.assertEqual(uut.ip_address, '10.0.0.1')
        self.assertEqual(uut.hostname, 'hostname_1')
        self.assertEqual(uut.tags, [])
