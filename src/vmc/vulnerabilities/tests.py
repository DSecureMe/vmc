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
from vmc.knowledge_base.documents import CveDocument

from vmc.elasticsearch import Search
from vmc.elasticsearch.tests import ESTestCase
from vmc.assets.documents import Impact as AssetImpact, AssetDocument
from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.config.test_settings import elastic_configured
from vmc.vulnerabilities.apps import VulnerabilitiesConfig

from vmc.knowledge_base import metrics
from vmc.vulnerabilities import utils


def create_cve(cve_id='CVE-2017-0002') -> CveDocument:
    cve = CveDocument(
        id=cve_id,
        base_score_v2=6.8,
        access_vector_v2=metrics.AccessVectorV2.NETWORK,
        access_complexity_v2=metrics.AccessComplexityV2.MEDIUM,
        authentication_v2=metrics.AuthenticationV2.NONE,
        confidentiality_impact_v2=metrics.ImpactV2.PARTIAL,
        integrity_impact_v2=metrics.ImpactV2.PARTIAL,
        availability_impact_v2=metrics.ImpactV2.PARTIAL,
        base_score_v3=8.8,
        attack_vector_v3=metrics.AttackVectorV3.NETWORK,
        attack_complexity_v3=metrics.AttackComplexityV3.LOW,
        privileges_required_v3=metrics.PrivilegesRequiredV3.NONE,
        user_interaction_v3=metrics.UserInteractionV3.REQUIRED,
        scope_v3=metrics.ScopeV3.UNCHANGED,
        confidentiality_impact_v3=metrics.ImpactV3.HIGH,
        integrity_impact_v3=metrics.ImpactV3.HIGH,
        availability_impact_v3=metrics.ImpactV3.HIGH
    )
    cve.save(refresh=True)
    return cve


def create_asset(ip_address='10.10.10.10') -> AssetDocument:
    asset = AssetDocument(
        id=ip_address,
        ip_address=ip_address,
        mac_address='mac_address',
        os='OS',
        hostname='HOSTNAME',
        confidentiality_requirement=AssetImpact.LOW,
        integrity_requirement=AssetImpact.LOW,
        availability_requirement=AssetImpact.LOW
    )
    asset.save(refresh=True)
    return asset


def create_vulnerability(asset, cve):
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
    return vulnerability.save(refresh=True)


class ConfigMock:
    def __init__(self):
        self.name = 'test'
        self.tenant = None


class VulnerabilitiesConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(VulnerabilitiesConfig.name, 'vmc.vulnerabilities')


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CalculateEnvironmentalScore(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        self.cve = create_cve()
        self.asset = create_asset()

    def change_scope(self, scope):
        self.cve.scope_v3 = scope.value

    def prepare_asset(self, cr, ir, ar):
        self.asset.confidentiality_requirement = cr
        self.asset.integrity_requirement = ir
        self.asset.availability_requirement = ar

    @parameterized.expand([
        (AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2),

        (AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, AssetImpact.LOW, utils.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2),
        (AssetImpact.LOW, AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2),

        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.LOW, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2),
        (AssetImpact.LOW, AssetImpact.NOT_DEFINED, AssetImpact.LOW, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2),

        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2),

        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.HIGH, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),
        (AssetImpact.LOW, AssetImpact.HIGH, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),
        (AssetImpact.HIGH, AssetImpact.LOW, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.NOT_DEFINED, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),
        (AssetImpact.HIGH, AssetImpact.MEDIUM, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.MEDIUM, utils.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2),

        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, utils.COLLATERAL_DAMAGE_POTENTIAL_HIGH_V2),
    ])
    def test_collateral_damage_potential_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.assertEqual(utils.collateral_damage_potential_v2(self.asset), expected)

    @parameterized.expand([
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, 5.4),
        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.LOW, 7.0),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.LOW, 7.0),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, 7.0),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.LOW, 7.4),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, 7.8),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, 9.1),
        (AssetImpact.NOT_DEFINED, AssetImpact.HIGH, AssetImpact.LOW, 8.1),
    ])
    def test_environmental_score_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.assertEqual(utils.environmental_score_v2(self.cve, self.asset), expected)

    @parameterized.expand([
        (metrics.ScopeV3.UNCHANGED, AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, 6.9),
        (metrics.ScopeV3.CHANGED, AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.LOW, 9.1),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.LOW, 7.8),
        (metrics.ScopeV3.CHANGED, AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, 9.1),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.LOW, 8.4),
        (metrics.ScopeV3.CHANGED, AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, 9.6),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, 8.8),
        (metrics.ScopeV3.CHANGED, AssetImpact.NOT_DEFINED, AssetImpact.HIGH, AssetImpact.LOW, 9.6),
    ])
    def test_environmental_score_v3(self, scope, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.change_scope(scope)
        self.assertEqual(utils.environmental_score_v3(self.cve, self.asset), expected)


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

        self.assertEqual(uut.environmental_score_v2, 5.4)
        self.assertEqual(uut.environmental_score_v3, 6.9)

    def test_asset_updated(self):
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset, self.cve)

        self.cve_2 = create_cve('CVE-2017-0003')
        create_vulnerability(self.asset, self.cve_2)
        create_vulnerability(self.asset, self.cve_2)
        create_vulnerability(self.asset, self.cve_2)
        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 6)

        self.asset.confidentiality_requirement = AssetImpact.HIGH
        self.asset.integrity_requirement = AssetImpact.HIGH
        self.asset.save(refresh=True)

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 6)

        result_1 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()

        self.assertEqual(len(result_1.hits), 3)
        self.assertEqual(result_1.hits[0].asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(result_1.hits[0].asset.integrity_requirement, self.asset.integrity_requirement)
        self.assertEqual(result_1.hits[0].environmental_score_v2, 8.5)
        self.assertEqual(result_1.hits[0].environmental_score_v3, 8.8)
        self.assertTrue(result_1.hits[0].modified_date > result_1.hits[1].modified_date)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve_2.id).execute()

        self.assertEqual(len(result_2.hits), 3)
        self.assertEqual(result_2.hits[0].asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(result_2.hits[0].environmental_score_v2, 8.5)
        self.assertEqual(result_2.hits[0].environmental_score_v3, 8.8)
        self.assertTrue(result_2.hits[0].modified_date > result_2.hits[1].modified_date)

    def test_cve_updated(self):
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset, self.cve)
        create_vulnerability(self.asset, self.cve)

        self.asset_2 = create_asset('10.10.10.11')
        create_vulnerability(self.asset_2, self.cve)
        create_vulnerability(self.asset_2, self.cve)
        create_vulnerability(self.asset_2, self.cve)
        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 6)

        self.cve.access_vector_v2 = metrics.AccessVectorV2.LOCAL
        self.cve.save(refresh=True)

        self.assertEqual(Search().index(VulnerabilityDocument.Index.name).count(), 6)

        result_1 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()

        self.assertEqual(len(result_1.hits), 3)
        self.assertEqual(result_1.hits[0].cve.access_vector_v2, self.cve.access_vector_v2)
        self.assertEqual(result_1.hits[0].environmental_score_v2, 3.2)
        self.assertEqual(result_1.hits[0].environmental_score_v3, 6.9)
        self.assertTrue(result_1.hits[0].modified_date > result_1.hits[1].modified_date)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset_2.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()

        self.assertEqual(len(result_2.hits), 3)
        self.assertEqual(result_2.hits[0].cve.access_vector_v2, self.cve.access_vector_v2)
        self.assertEqual(result_2.hits[0].environmental_score_v2, 3.2)
        self.assertEqual(result_2.hits[0].environmental_score_v3, 6.9)
        self.assertTrue(result_2.hits[0].modified_date > result_2.hits[1].modified_date)

    def test_update_existing_vulnerability(self):
        vuln = create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        updated_vuln = vuln.clone()
        updated_vuln.description = 'Updated Desc'

        VulnerabilityDocument.create_or_update({updated_vuln.id: updated_vuln}, [], ConfigMock())
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()
        self.assertEqual(result_2.hits[0].description, 'Updated Desc')

    def test_not_updated_existing_vulnerability(self):
        vuln = create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        updated_vuln = vuln.clone()

        VulnerabilityDocument.create_or_update({updated_vuln.id: updated_vuln}, [], ConfigMock())
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').filter(
            'term', cve__id=self.cve.id).execute()
        self.assertEqual(result_2.hits[0].description, 'description')

    def test_fixed_vulnerability(self):
        create_vulnerability(self.asset, self.cve)
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        VulnerabilityDocument.create_or_update({}, [self.asset.ip_address], ConfigMock())
        self.assertEqual(VulnerabilityDocument.search().count(), 1)

        result_2 = VulnerabilityDocument.search().filter(
            'term', asset__ip_address=self.asset.ip_address).sort('-modified_date').execute()

        self.assertEqual(result_2.hits[0].tags, ['test', 'FIXED'])
