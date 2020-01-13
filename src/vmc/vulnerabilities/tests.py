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
from vmc.assets.documents import Impact as AssetImpact
from vmc.vulnerabilities.documents import VulnerabilityDocument, CveDocument, AssetDocument

from vmc.config.test_settings import elastic_configured
from vmc.vulnerabilities.apps import VulnerabilitiesConfig

from vmc.knowledge_base import metrics
from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


def create_cve() -> CveDocument:
    return CveDocument(
        id='CVE-2017-0002',
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


def create_asset() -> AssetDocument:
    return AssetDocument(
        ip_address='10.10.10.10',
        mac_address='mac_address',
        os='OS',
        business_owner='business_owner',
        technical_owner='technical_owner',
        hostname='HOSTNAME',
        confidentiality_requirement=AssetImpact.LOW,
        integrity_requirement=AssetImpact.LOW,
        availability_requirement=AssetImpact.LOW
    )


class VulnerabilitiesConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(VulnerabilitiesConfig.name, 'vmc.vulnerabilities')


class CalculateEnvironmentalScore(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.cve = create_cve()
        cls.asset = create_asset()

    def change_scope(self, scope):
        self.cve.scope_v3 = scope.value

    def prepare_asset(self, cr, ir, ar):
        self.asset.confidentiality_requirement = cr
        self.asset.integrity_requirement = ir
        self.asset.availability_requirement = ar

    @parameterized.expand([
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, 4.9),
        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.LOW, 5.7),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.LOW, 5.7),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, 5.7),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.LOW, 6.3),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, 6.8),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, 8.2),
        (AssetImpact.NOT_DEFINED, AssetImpact.HIGH, AssetImpact.LOW, 6.9),
    ])
    def test_environmental_score_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.assertEqual(environmental_score_v2(self.cve, self.asset), expected)

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
        self.assertEqual(environmental_score_v3(self.cve, self.asset), expected)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class VulnerabilityDocumentTest(ESTestCase, TestCase):

    @classmethod
    def create_vulnerability(cls):
        cls.cve = create_cve()
        cls.asset = create_asset()
        cls.vulnerability = VulnerabilityDocument(
            asset=cls.asset,
            cve=cls.cve,
            description='description',
            solution='solution',
            port=22,
            svc_name='ssh',
            protocol='tcp'
        )
        cls.vulnerability.save(refresh=True)

    def test_document_index_name(self):
        self.assertEqual(VulnerabilityDocument.Index.name, 'vulnerability')

    def test_document_fields(self):
        self.create_vulnerability()
        search = VulnerabilityDocument.search().filter('term', port=self.vulnerability.port).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.cve.id, self.vulnerability.cve.id)
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
        self.assertEqual(uut.asset.os, self.vulnerability.asset.os)
        self.assertEqual(uut.asset.confidentiality_requirement, self.asset.confidentiality_requirement)
        self.assertEqual(uut.asset.integrity_requirement, self.asset.integrity_requirement)
        self.assertEqual(uut.asset.availability_requirement, self.asset.availability_requirement)

        self.assertEqual(uut.port, self.vulnerability.port)
        self.assertEqual(uut.svc_name, self.vulnerability.svc_name)
        self.assertEqual(uut.protocol, self.vulnerability.protocol)

        self.assertEqual(uut.environmental_score_v2, 4.9)
        self.assertEqual(uut.environmental_score_v3, 6.9)
