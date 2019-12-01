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

from django.test import TestCase
from parameterized import parameterized

from vmc.assets import models as as_models
from vmc.knowledge_base import models as nvd_models
from vmc.knowledge_base import metrics
from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


class CalculateEnvironmentalScore(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.cve = nvd_models.Cve.objects.create(
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
