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
from vmc.assets.apps import AssetsConfig

from vmc.assets.documents import AssetDocument

from vmc.config.test_settings import elastic_configured
from vmc.assets.models import Port, Asset, Impact


class AssetsConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(AssetsConfig.name, 'vmc.assets')


class PortTest(TestCase):
    fixtures = ['assets.json']

    @classmethod
    def setUpTestData(cls):
        cls.uut = Port.objects.get(pk=1)

    def test_str_call(self):
        self.assertEqual(self.uut.__str__(), "22")


class AssetTest(TestCase):
    fixtures = ['assets.json']

    @classmethod
    def setUpTestData(cls):
        cls.uut = Asset.objects.get(pk=1)

    def test_call(self):
        self.assertEqual(self.uut.__str__(), '10.10.10.1')
        self.assertEqual(self.uut.confidentiality_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_confidentiality_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_confidentiality_requirement_value(), Impact.NOT_DEFINED.float)

        self.assertEqual(self.uut.integrity_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_integrity_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_integrity_requirement_value(), Impact.NOT_DEFINED.float)

        self.assertEqual(self.uut.availability_requirement, Impact.NOT_DEFINED.value)
        self.assertEqual(self.uut.get_availability_requirement_display(), Impact.NOT_DEFINED.name)
        self.assertEqual(self.uut.get_availability_requirement_value(), Impact.NOT_DEFINED.float)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class AssetDocumentTest(TestCase):
    fixtures = ['assets.json']

    def test_model_class_added(self):
        self.assertEqual(AssetDocument.django.model, Asset.history.model)

    def test_document_index_name(self):
        self.assertEqual(AssetDocument.Index.name, 'asset')

    def test_document(self):
        self.change_imported_object()
        search = AssetDocument.search().filter("term", ip_address="10.10.10.1").execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.os, 'Windows')
        self.assertEqual(uut.confidentiality_requirement, 'NOT_DEFINED')
        self.assertEqual(uut.integrity_requirement, 'NOT_DEFINED')
        self.assertEqual(uut.availability_requirement, 'NOT_DEFINED')
        self.assertEqual(uut.business_owner, 'test-business_owner')
        self.assertEqual(uut.technical_owner, 'test-technical_owner')
        self.assertEqual(uut.hostname, 'test-hostname')
        self.assertTrue(uut.created_date)
        self.assertTrue(uut.modified_date)
        prev_date = uut.modified_date

        self.change_imported_object(hostname='test-hostname2')
        search = AssetDocument.search().filter("term", ip_address="10.10.10.1").execute()
        self.assertEqual(len(search.hits), 2)

        uut = search.hits[1]
        self.assertEqual(uut.hostname, 'test-hostname2')
        self.assertNotEqual(uut.modified_date, prev_date)

    @staticmethod
    def change_imported_object(hostname='test-hostname'):
        asset = Asset.objects.get(pk=1)
        asset.hostname = hostname
        asset.save()
