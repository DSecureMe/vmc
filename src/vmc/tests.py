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
from unittest import skipIf

from django.test import TestCase


from vmc.apps import VMCConfig
from vmc.elasticsearch.tests import ESTestCase
from vmc.config.test_settings import elastic_configured

from vmc.ralph.models import Config as RalphConfig
from vmc.assets.documents import AssetDocument


class VMCConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(VMCConfig.name, 'vmc')


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class TenantTest(ESTestCase, TestCase):
    fixtures = ['tenant_test.json']

    def setUp(self):
        super().setUp()
        self.config_tenant_1 = RalphConfig.objects.get(id=1)
        self.config_tenant_2 = RalphConfig.objects.get(id=2)

    def create_asset(self, tags):
        return AssetDocument(
            ip_address='10.10.10.1',
            os='Windows',
            id=1,
            confidentiality_requirement='NOT_DEFINED',
            integrity_requirement='NOT_DEFINED',
            availability_requirement='NOT_DEFINED',
            hostname='test-hostname',
            tags=[tags]
        )

    def test_update_asset(self):
        asset_tenant_1 = self.create_asset(self.config_tenant_1.name)
        asset_tenant_2 = self.create_asset(self.config_tenant_2.name)
        AssetDocument.create_or_update({asset_tenant_1.id: asset_tenant_1}, self.config_tenant_1)
        AssetDocument.create_or_update({asset_tenant_2.id: asset_tenant_2}, self.config_tenant_2)

        asset_tenant_1 = self.create_asset(self.config_tenant_1.name)
        asset_tenant_1.hostname = 'tenant-test'
        AssetDocument.create_or_update({asset_tenant_1.id: asset_tenant_1}, self.config_tenant_1)

        result = AssetDocument.search(index='test.tenant.asset').filter('term', ip_address='10.10.10.1').execute()
        self.assertEqual(1, len(result.hits))
        self.assertEqual(result.hits[0].ip_address, '10.10.10.1')
        self.assertEqual(result.hits[0].hostname, 'tenant-test')
