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
from django_elasticsearch_dsl.test import ESTestCase
from parameterized import parameterized

from vmc.vulnerabilities.models import Vulnerability

from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.config.test_settings import elastic_configured
from vmc.vulnerabilities.apps import VulnerabilitiesConfig

from vmc.assets import models as as_models
from vmc.knowledge_base import models as nvd_models
from vmc.knowledge_base import metrics
from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


def create_cve() -> nvd_models.Cve:
    return nvd_models.Cve.objects.create(
        id='CVE-2017-0002',
        base_score_v2=6.8,
        access_vector_v2=metrics.AccessVectorV2.NETWORK.value,
        access_complexity_v2=metrics.AccessComplexityV2.MEDIUM.value,
        authentication_v2=metrics.AuthenticationV2.NONE.value,
        confidentiality_impact_v2=metrics.ImpactV2.PARTIAL.value,
        integrity_impact_v2=metrics.ImpactV2.PARTIAL.value,
        availability_impact_v2=metrics.ImpactV2.PARTIAL.value,
        base_score_v3=8.8,
        attack_vector_v3=metrics.AttackVectorV3.NETWORK.value,
        attack_complexity_v3=metrics.AttackComplexityV3.LOW.value,
        privileges_required_v3=metrics.PrivilegesRequiredV3.NONE.value,
        user_interaction_v3=metrics.UserInteractionV3.REQUIRED.value,
        scope_v3=metrics.ScopeV3.UNCHANGED.value,
        confidentiality_impact_v3=metrics.ImpactV3.HIGH.value,
        integrity_impact_v3=metrics.ImpactV3.HIGH.value,
        availability_impact_v3=metrics.ImpactV3.HIGH.value
    )


class VulnerabilitiesConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(VulnerabilitiesConfig.name, 'vmc.vulnerabilities')


class CalculateEnvironmentalScore(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.cve = create_cve()
        cls.asset = None

    def prepare_asset(self, cr, ir, ar):
        self.asset = as_models.Asset.objects.create(
            ip_address='10.10.10.10',
            confidentiality_requirement=cr.value,
            integrity_requirement=ir.value,
            availability_requirement=ar.value
        )

    def change_scope(self, scope):
        self.cve.scope_v3 = scope.value
        self.cve.save()

    @parameterized.expand([
        (as_models.Impact.LOW, as_models.Impact.LOW, as_models.Impact.LOW, 4.9),
        (as_models.Impact.MEDIUM, as_models.Impact.LOW, as_models.Impact.LOW, 5.7),
        (as_models.Impact.LOW, as_models.Impact.MEDIUM, as_models.Impact.LOW, 5.7),
        (as_models.Impact.LOW, as_models.Impact.LOW, as_models.Impact.MEDIUM, 5.7),
        (as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, as_models.Impact.LOW, 6.3),
        (as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, 6.8),
        (as_models.Impact.HIGH, as_models.Impact.HIGH, as_models.Impact.HIGH, 8.2),
        (as_models.Impact.NOT_DEFINED, as_models.Impact.HIGH, as_models.Impact.LOW, 6.9),
    ])
    def test_environmental_score_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.assertEqual(environmental_score_v2(self.cve, self.asset), expected)

    @parameterized.expand([
        (metrics.ScopeV3.UNCHANGED, as_models.Impact.LOW, as_models.Impact.LOW, as_models.Impact.LOW, 6.9),
        (metrics.ScopeV3.CHANGED, as_models.Impact.MEDIUM, as_models.Impact.LOW, as_models.Impact.LOW, 9.1),
        (metrics.ScopeV3.UNCHANGED, as_models.Impact.LOW, as_models.Impact.MEDIUM, as_models.Impact.LOW, 7.8),
        (metrics.ScopeV3.CHANGED, as_models.Impact.LOW, as_models.Impact.LOW, as_models.Impact.MEDIUM, 9.1),
        (metrics.ScopeV3.UNCHANGED, as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, as_models.Impact.LOW, 8.4),
        (metrics.ScopeV3.CHANGED, as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, as_models.Impact.MEDIUM, 9.6),
        (metrics.ScopeV3.UNCHANGED, as_models.Impact.HIGH, as_models.Impact.HIGH, as_models.Impact.HIGH, 8.8),
        (metrics.ScopeV3.CHANGED, as_models.Impact.NOT_DEFINED, as_models.Impact.HIGH, as_models.Impact.LOW, 9.6),
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
        cls.asset = as_models.Asset.objects.create(
            ip_address='10.10.10.10',
            mac_address='mac_address',
            os='OS',
            business_owner='business_owner',
            technical_owner='technical_owner',
            hostname='HOSTNAME',
            confidentiality_requirement=as_models.Impact.LOW.value,
            integrity_requirement=as_models.Impact.LOW.value,
            availability_requirement=as_models.Impact.LOW.value
        )
        cls.vulnerability = Vulnerability.objects.create(
            asset=cls.asset,
            cve=cls.cve,
            description='description',
            solution='solution',
            exploit_available=False,
            port=22,
            svc_name='ssh',
            protocol='tcp'
        )

    def test_model_class_added(self):
        self.assertEqual(VulnerabilityDocument.Django.model, Vulnerability)

    def test_document_index_name(self):
        self.assertEqual(VulnerabilityDocument.Index.name, 'vulnerability')

    def test_related_models(self):
        self.assertEqual(VulnerabilityDocument.Django.related_models, [as_models.Asset, nvd_models.Cve])

    def test_document_fields(self):
        self.create_vulnerability()
        search = VulnerabilityDocument.search().filter('term', port=self.vulnerability.port).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.cve.id, self.vulnerability.cve.id)
        self.assertEqual(uut.cve.base_score_v2, self.vulnerability.cve.base_score_v2)
        self.assertEqual(uut.cve.base_score_v3, self.vulnerability.cve.base_score_v3)
        self.assertEqual(uut.cve.summary, self.vulnerability.cve.summary)
        self.assertEqual(uut.cve.access_vector_v2, self.vulnerability.cve.get_access_vector_v2_display())
        self.assertEqual(uut.cve.access_complexity_v2, self.vulnerability.cve.get_access_complexity_v2_display())
        self.assertEqual(uut.cve.authentication_v2, self.vulnerability.cve.get_authentication_v2_display())
        self.assertEqual(uut.cve.confidentiality_impact_v2, self.vulnerability.cve.get_confidentiality_impact_v2_display())
        self.assertEqual(uut.cve.integrity_impact_v2, self.vulnerability.cve.get_integrity_impact_v2_display())
        self.assertEqual(uut.cve.availability_impact_v2, self.vulnerability.cve.get_availability_impact_v2_display())
        self.assertEqual(uut.cve.attack_vector_v3, self.vulnerability.cve.get_attack_vector_v3_display())
        self.assertEqual(uut.cve.attack_complexity_v3, self.vulnerability.cve.get_attack_complexity_v3_display())
        self.assertEqual(uut.cve.privileges_required_v3, self.vulnerability.cve.get_privileges_required_v3_display())
        self.assertEqual(uut.cve.user_interaction_v3, self.vulnerability.cve.get_user_interaction_v3_display())
        self.assertEqual(uut.cve.scope_v3, self.vulnerability.cve.get_scope_v3_display())
        self.assertEqual(uut.cve.confidentiality_impact_v3, self.vulnerability.cve.get_confidentiality_impact_v3_display())
        self.assertEqual(uut.cve.integrity_impact_v3, self.vulnerability.cve.get_integrity_impact_v3_display())
        self.assertEqual(uut.cve.availability_impact_v3, self.vulnerability.cve.get_availability_impact_v3_display())

        self.assertEqual(uut.asset.ip_address, self.vulnerability.asset.ip_address)
        self.assertEqual(uut.asset.mac_address, self.vulnerability.asset.mac_address)
        self.assertEqual(uut.asset.os, self.vulnerability.asset.os)
        self.assertEqual(uut.asset.confidentiality_requirement, self.vulnerability.asset.get_confidentiality_requirement_display())
        self.assertEqual(uut.asset.integrity_requirement, self.vulnerability.asset.get_integrity_requirement_display())
        self.assertEqual(uut.asset.availability_requirement, self.vulnerability.asset.get_availability_requirement_display())

        self.assertEqual(uut.port, self.vulnerability.port)
        self.assertEqual(uut.svc_name, self.vulnerability.svc_name)
        self.assertEqual(uut.protocol, self.vulnerability.protocol)

        self.assertEqual(uut.environmental_score_v2, 4.9)
        self.assertEqual(uut.environmental_score_v3, 6.9)
