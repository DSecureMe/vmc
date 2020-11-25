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

from django.contrib.auth.models import User
from django.test import TestCase, LiveServerTestCase
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from vmc.knowledge_base.tests import create_cve
from vmc.common.utils import thread_pool_executor
from vmc.config.test_settings import elastic_configured
from vmc.elasticsearch import Search
from vmc.elasticsearch.tests import ESTestCase
from vmc.knowledge_base import metrics
from vmc.assets.documents import Impact as AssetImpact
from vmc.assets.tests import create_asset
from vmc.vulnerabilities.apps import VulnerabilitiesConfig
from vmc.vulnerabilities.documents import VulnerabilityDocument, VulnerabilityStatus


def create_vulnerability(asset, cve, save=True, index=None):
    vulnerability = VulnerabilityDocument(
        id=F"{asset.id}-{cve.id}",
        asset=asset,
        cve=cve,
        description='description',
        solution='solution',
        port=22,
        svc_name='ssh',
        protocol='tcp',
        tags=['test']
    )
    if save:
        vulnerability.save(index=index)
    return vulnerability


class ConfigMock:
    def __init__(self):
        self.name = 'test'
        self.tenant = None


class VulnerabilitiesConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(VulnerabilitiesConfig.name, 'vmc.vulnerabilities')


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class VulnerabilityDocumentTest(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        self.cve = create_cve()
        self.asset = create_asset()

    def test_document_index_name(self):
        self.assertEqual(VulnerabilityDocument.Index.name, 'vulnerability')

    def test_document_fields(self):
        create_vulnerability(self.asset, self.cve)
        search = VulnerabilityDocument.search().filter('term', port=22).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.cve.id, self.cve.id)
        self.assertEqual(uut.cve.base_score_v2, self.cve.base_score_v2)
        self.assertEqual(uut.cve.base_score_v3, self.cve.base_score_v3)
        self.assertEqual(uut.cve.summary, self.cve.summary)
        self.assertEqual(uut.cve.access_vector_v2, self.cve.access_vector_v2)
        self.assertEqual(uut.cve.access_complexity_v2, self.cve.access_complexity_v2)
        self.assertEqual(uut.cve.authentication_v2, self.cve.authentication_v2)
        self.assertEqual(uut.cve.confidentiality_impact_v2, self.cve.confidentiality_impact_v2)
        self.assertEqual(uut.cve.integrity_impact_v2, self.cve.integrity_impact_v2)
        self.assertEqual(uut.cve.availability_impact_v2, self.cve.availability_impact_v2)
        self.assertEqual(uut.cve.attack_vector_v3, self.cve.attack_vector_v3)
        self.assertEqual(uut.cve.attack_complexity_v3, self.cve.attack_complexity_v3)
        self.assertEqual(uut.cve.privileges_required_v3, self.cve.privileges_required_v3)
        self.assertEqual(uut.cve.user_interaction_v3, self.cve.user_interaction_v3)
        self.assertEqual(uut.cve.scope_v3, self.cve.scope_v3)
        self.assertEqual(uut.cve.confidentiality_impact_v3, self.cve.confidentiality_impact_v3)
        self.assertEqual(uut.cve.integrity_impact_v3, self.cve.integrity_impact_v3)
        self.assertEqual(uut.cve.availability_impact_v3, self.cve.availability_impact_v3)

        self.assertEqual(uut.asset.ip_address, self.asset.ip_address)
        self.assertEqual(uut.asset.mac_address, self.asset.mac_address)
        self.assertEqual(uut.asset.os, self.asset.os)
        self.assertEqual(uut.asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(uut.asset.integrity_requirement, self.asset.integrity_requirement)
        self.assertEqual(uut.asset.availability_requirement, self.asset.availability_requirement)

        self.assertEqual(uut.port, 22)
        self.assertEqual(uut.svc_name, 'ssh')
        self.assertEqual(uut.protocol, 'tcp')

    def test_asset_updated(self):
        self.asset_2 = create_asset('10.10.10.11')
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset_2, self.cve)

        self.cve_2 = create_cve('CVE-2017-0003')
        create_vulnerability(self.asset, self.cve_2)
        create_vulnerability(self.asset_2, self.cve_2)

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 4)

        self.asset.confidentiality_requirement = AssetImpact.HIGH
        self.asset.integrity_requirement = AssetImpact.HIGH
        self.asset.save()
        thread_pool_executor.wait_for_all()

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 4)

        result_1 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).execute()

        self.assertEqual(len(result_1.hits), 2)
        self.assertEqual(result_1.hits[0].asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(result_1.hits[0].asset.integrity_requirement, self.asset.integrity_requirement)
        self.assertEqual(result_1.hits[1].asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(result_1.hits[1].asset.integrity_requirement, self.asset.integrity_requirement)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset_2.ip_address).execute()

        self.assertEqual(len(result_2.hits), 2)
        self.assertEqual(result_2.hits[0].asset.confidentiality_requirement, self.asset_2.confidentiality_requirement)
        self.assertEqual(result_2.hits[0].asset.integrity_requirement, self.asset_2.integrity_requirement)
        self.assertEqual(result_2.hits[1].asset.confidentiality_requirement, self.asset_2.confidentiality_requirement)
        self.assertEqual(result_2.hits[1].asset.integrity_requirement, self.asset_2.integrity_requirement)

    def test_cve_updated(self):
        self.asset_2 = create_asset('10.10.10.11')
        self.cve_2 = create_cve('CVE-2017-0003')
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset, self.cve_2)

        create_vulnerability(self.asset_2, self.cve)
        create_vulnerability(self.asset_2, self.cve_2)

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 4)

        self.cve.access_vector_v2 = metrics.AccessVectorV2.LOCAL
        self.cve.save()
        thread_pool_executor.wait_for_all()

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 4)

        result_1 = VulnerabilityDocument.search().filter('term', cve__id=self.cve.id).execute()

        self.assertEqual(len(result_1.hits), 2)
        self.assertNotEqual(result_1.hits[0].created_date, result_1.hits[0].modified_date)
        self.assertEqual(result_1.hits[0].cve.access_vector_v2, self.cve.access_vector_v2)
        self.assertEqual(result_1.hits[1].cve.access_vector_v2, self.cve.access_vector_v2)

        result_2 = VulnerabilityDocument.search().filter('term', cve__id=self.cve_2.id).execute()

        self.assertEqual(len(result_2.hits), 2)
        self.assertEqual(result_2.hits[0].cve.access_vector_v2, self.cve_2.access_vector_v2)
        self.assertEqual(result_2.hits[1].cve.access_vector_v2, self.cve_2.access_vector_v2)

    def test_update_existing_vulnerability(self):
        vuln = create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        updated_vuln = vuln.clone()
        updated_vuln.description = 'Updated Desc'

        VulnerabilityDocument.create_or_update({updated_vuln.id: updated_vuln}, [], ConfigMock())
        thread_pool_executor.wait_for_all()
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).filter(
            'term', cve__id=self.cve.id).execute()
        self.assertEqual(result_2.hits[0].description, 'Updated Desc')

    def test_not_updated_existing_vulnerability(self):
        vuln = create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        updated_vuln = vuln.clone()

        VulnerabilityDocument.create_or_update({updated_vuln.id: updated_vuln}, [], ConfigMock())
        thread_pool_executor.wait_for_all()
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()
        self.assertEqual(result_2.hits[0].description, 'description')

    def test_fixed_vulnerability(self):
        create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        VulnerabilityDocument.create_or_update({}, [self.asset.ip_address], ConfigMock())
        thread_pool_executor.wait_for_all()
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).execute()

        self.assertEqual(result_2.hits[0].tags, ['test', VulnerabilityStatus.FIXED])

    def test_reopen_vulnerability(self):
        vulnerability = create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        VulnerabilityDocument.create_or_update({}, [self.asset.ip_address], ConfigMock())
        thread_pool_executor.wait_for_all()
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).execute()

        self.assertEqual(result.hits[0].tags, ['test', VulnerabilityStatus.FIXED])

        VulnerabilityDocument.create_or_update({vulnerability.id: vulnerability}, [self.asset.ip_address], ConfigMock())
        thread_pool_executor.wait_for_all()
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).execute()

        self.assertEqual(result.hits[0].tags, ['test', VulnerabilityStatus.REOPEN])


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class SearchVulnerabilitiesTest(ESTestCase, LiveServerTestCase):
    fixtures = ['users.json', 'tenant_test.json']
    URL = reverse('search_vulnerabilities')

    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.get(pk=1)
        self.client = APIClient()

    def test_auth_missing(self):
        resp = self.client.get(self.URL)
        self.assertEqual(resp.status_code, 401)

    def test_call_get_without_param(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(self.URL)
        self.assertEqual(resp.status_code, 404)

    def test_call_search_invalid_ip_address(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?ip_address=aaaaaaaaaaa')
        self.assertEqual(resp.status_code, 404)

    def test_call_post(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.post(F'{self.URL}?ip_address=aaaaaaaaaaa')
        self.assertEqual(resp.status_code, 405)

    def test_call_ip_not_found(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?ip_address=10.10.10.1')
        self.assertEqual(resp.status_code, 200)
        resp = resp.json()

        self.assertEqual(len(resp), 0)

    def test_call_without_tenant(self):
        asset = create_asset()
        cve = create_cve()
        vuln = create_vulnerability(asset, cve)
        create_vulnerability(asset, cve, index='test.tenant.vulnerability')

        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?ip_address={asset.ip_address}')
        self.assertEqual(resp.status_code, 200)
        resp = resp.json()

        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]['port'], vuln.port)
        self.assertEqual(resp[0]['svc_name'], vuln.svc_name)
        self.assertEqual(resp[0]['protocol'], vuln.protocol)
        self.assertEqual(resp[0]['description'], vuln.description)
        self.assertEqual(resp[0]['environmental_score_v2'], vuln.environmental_score_v2)
        self.assertEqual(resp[0]['environmental_score_vector_v2'], vuln.environmental_score_vector_v2)
        self.assertEqual(resp[0]['environmental_score_v3'], vuln.environmental_score_v3)
        self.assertEqual(resp[0]['environmental_score_vector_v3'], vuln.environmental_score_vector_v3)
        self.assertEqual(resp[0]['tags'], vuln.tags)
        self.assertEqual(resp[0]['source'], vuln.source)
        self.assertEqual(resp[0]['cve'], vuln.cve.id)
        self.assertEqual(resp[0]['summary'], vuln.cve.summary)
        self.assertEqual(resp[0]['base_score_v2'], vuln.cve.base_score_v2)
        self.assertEqual(resp[0]['base_score_v3'], vuln.cve.base_score_v3)

    def test_call_not_existing_tenant(self):
        asset = create_asset()
        cve = create_cve()
        create_vulnerability(asset, cve)

        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?ip_address={asset.ip_address}&tenant=aaaaa')
        self.assertEqual(resp.status_code, 404)

    def test_call_tenant(self):
        asset = create_asset()
        cve = create_cve()
        create_vulnerability(asset, cve, index='test.tenant.vulnerability')

        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        resp = self.client.get(F'{self.URL}?ip_address={asset.ip_address}&tenant=Tenant')
        self.assertEqual(resp.status_code, 200)
        resp = resp.json()

        self.assertEqual(len(resp), 1)
