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

from elasticsearch.helpers import bulk
from elasticsearch_dsl.connections import get_connection

from vmc.config.test_settings import elastic_configured
from vmc.assets.documents import Impact as AssetImpact, AssetStatus, AssetDocument
from vmc.assets.tests import create_asset
from vmc.knowledge_base import metrics
from vmc.knowledge_base.documents import CveDocument
from vmc.knowledge_base.tests import create_cve
from vmc.elasticsearch.tests import ESTestCase
from vmc.vulnerabilities.documents import VulnerabilityDocument, VulnerabilityStatus
from vmc.vulnerabilities.tests import create_vulnerability

from vmc.processing.apps import ProcessingConfig
from vmc.processing import tasks


class ProcessingConfigTest(TestCase):

    def test_name(self):
        self.assertEqual(ProcessingConfig.name, 'vmc.processing')


class CalculateEnvironmentalScoreHelpersTests(TestCase):

    def setUp(self):
        self.cve = create_cve(save=False)
        self.asset = create_asset(save=False)

    def change_scope(self, scope):
        self.cve.scope_v3 = scope.value

    def prepare_asset(self, cr, ir, ar):
        self.asset.confidentiality_requirement = cr
        self.asset.integrity_requirement = ir
        self.asset.availability_requirement = ar

    @parameterized.expand([
        (AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2, 'ND')),

        (AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, AssetImpact.LOW, (tasks.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2, 'N')),
        (AssetImpact.LOW, AssetImpact.NOT_DEFINED, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2, 'N')),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_NONE_V2, 'N')),

        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2, 'L')),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.LOW, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2, 'L')),
        (AssetImpact.LOW, AssetImpact.NOT_DEFINED, AssetImpact.LOW, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2, 'L')),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_V2, 'L')),

        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),
        (AssetImpact.NOT_DEFINED, AssetImpact.LOW, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2, 'LM')),

        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.HIGH, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),
        (AssetImpact.LOW, AssetImpact.HIGH, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),
        (AssetImpact.HIGH, AssetImpact.LOW, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.NOT_DEFINED, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),
        (AssetImpact.HIGH, AssetImpact.MEDIUM, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.MEDIUM, (tasks.COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2, 'MH')),

        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, (tasks.COLLATERAL_DAMAGE_POTENTIAL_HIGH_V2, 'H')),
    ])
    def test_collateral_damage_potential_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.assertEqual(tasks.collateral_damage_potential_v2(self.asset), expected)

    @parameterized.expand([
        (0, 1, (tasks.TARGET_DISTRIBUTION_NONE_V2, 'N')),
        (1, 1000, (tasks.TARGET_DISTRIBUTION_NONE_V2, 'N')),
        (10, 1000, (tasks.TARGET_DISTRIBUTION_LOW_V2, 'L')),
        (240, 1000, (tasks.TARGET_DISTRIBUTION_LOW_V2, 'L')),
        (250, 1000, (tasks.TARGET_DISTRIBUTION_MEDIUM_V2, 'M')),
        (740, 1000, (tasks.TARGET_DISTRIBUTION_MEDIUM_V2, 'M')),
        (750, 1000, (tasks.TARGET_DISTRIBUTION_HIGH_V2, 'H')),
        (1000, 1000, (tasks.TARGET_DISTRIBUTION_HIGH_V2, 'H')),
    ])
    def test_target_distribution_v2(self, vuln_count, assets_cunt, expected):
        self.assertEqual(tasks.target_distribution_v2(vuln_count, assets_cunt), expected)

    def test_temporal_remediation_level_v2(self):
        self.assertEqual(tasks.temporal_remediation_level_v2(), tasks.TEMPORAL_REMEDIATION_LEVEL_NOT_DEFINED_V2)

    def test_temporal_report_confidence_v2(self):
        self.assertEqual(tasks.temporal_report_confidence_v2(), tasks.TEMPORAL_REPORT_CONFIDENCE_NOT_DEFINED_V2)

    def test_temporal_exploitability_v2(self):
        self.assertEqual(tasks.temporal_exploitability_v2(), tasks.TEMPORAL_EXPLOITABILITY_NOT_DEFINED_V2)

    @parameterized.expand([
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW, (5.4, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:L/TD:H/CR:L/IR:L/AR:L')),
        (AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.LOW, (7.0, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:LM/TD:H/CR:M/IR:L/AR:L')),
        (AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.LOW, (7.0, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:LM/TD:H/CR:L/IR:M/AR:L')),
        (AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM, (7.0, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:LM/TD:H/CR:L/IR:L/AR:M')),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.LOW, (7.4, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:LM/TD:H/CR:M/IR:M/AR:L')),
        (AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM, (7.8, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:LM/TD:H/CR:M/IR:M/AR:M')),
        (AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH, (9.1, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:H/TD:H/CR:H/IR:H/AR:H')),
        (AssetImpact.NOT_DEFINED, AssetImpact.HIGH, AssetImpact.LOW, (8.1, 'AV:N/AC:M/Au:N/C:P/I:P/A:P/CDP:MH/TD:H/CR:ND/IR:H/AR:L')),
    ])
    def test_calculate_environmental_score_v2(self, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        vuln = VulnerabilityDocument(cve=self.cve, asset=self.asset)
        self.assertEqual(tasks.calculate_environmental_score_v2(vuln, 100, 100), expected)

    @parameterized.expand([
        (metrics.AttackVectorV3.LOCAL,
         metrics.AttackComplexityV3.LOW,
         metrics.ScopeV3.UNCHANGED,
         metrics.PrivilegesRequiredV3.HIGH,
         metrics.UserInteractionV3.REQUIRED,
         0.58),
        (metrics.AttackVectorV3.LOCAL,
         metrics.AttackComplexityV3.LOW,
         metrics.ScopeV3.UNCHANGED,
         metrics.PrivilegesRequiredV3.HIGH,
         metrics.UserInteractionV3.NONE,
         0.8)
    ])
    def test_exploitability_v3(self, av, ac, scope, pr, ui, expected):
        cve = CveDocument(attack_vector_v3=av, attack_complexity_v3=ac, scope_v3=scope,
                          privileges_required_v3=pr, user_interaction_v3=ui)
        self.assertEqual(round(tasks.exploitability_v3(cve), 2), expected)

    def test_exploit_code_maturity_v3(self):
        self.assertEqual(tasks.exploit_code_maturity_v3(), tasks.EXPLOIT_CODE_MATURITY_NOT_DEFINED_V3)

    def test_remediation_level_v3(self):
        self.assertEqual(tasks.remediation_level_v3(), tasks.REMEDIATION_LEVEL_NOT_DEFINED_V3)

    def test_report_confidence_v3(self):
        self.assertEqual(tasks.report_confidence_v3(), tasks.REPORT_CONFIDENCE_NOT_DEFINED_V3)

    @parameterized.expand([
        (metrics.ScopeV3.UNCHANGED, AssetImpact.LOW, AssetImpact.LOW, AssetImpact.LOW,
         (6.9, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L')),
        (metrics.ScopeV3.CHANGED, AssetImpact.MEDIUM, AssetImpact.LOW, AssetImpact.LOW,
         (9.1, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:M/IR:L/AR:L')),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.LOW, AssetImpact.MEDIUM, AssetImpact.LOW,
         (7.8, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/CR:L/IR:M/AR:L')),
        (metrics.ScopeV3.CHANGED, AssetImpact.LOW, AssetImpact.LOW, AssetImpact.MEDIUM,
         (9.1, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:L/IR:L/AR:M')),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.LOW,
         (8.4, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/CR:M/IR:M/AR:L')),
        (metrics.ScopeV3.CHANGED, AssetImpact.MEDIUM, AssetImpact.MEDIUM, AssetImpact.MEDIUM,
         (9.7, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:M/IR:M/AR:M')),
        (metrics.ScopeV3.UNCHANGED, AssetImpact.HIGH, AssetImpact.HIGH, AssetImpact.HIGH,
         (8.8, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H')),
        (metrics.ScopeV3.CHANGED, AssetImpact.NOT_DEFINED, AssetImpact.HIGH, AssetImpact.LOW,
         (9.7, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:X/IR:H/AR:L')),
    ])
    def test_environmental_score_v3(self, scope, cr, ir, ar, expected):
        self.prepare_asset(cr, ir, ar)
        self.change_scope(scope)
        vuln = VulnerabilityDocument(cve=self.cve, asset=self.asset)
        self.assertEqual(tasks.calculate_environmental_score_v3(vuln), expected)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CalculateEnvironmentalScore(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        self.cve = create_cve(save=False)

    @staticmethod
    def generate_assets():
        docs = []
        for i in range(1000):
            docs.append(create_asset(F'10.10.10.{i}', save=False).to_dict())
        bulk(get_connection(), docs, refresh=True, index=AssetDocument.Index.name)

    def generate_vulns(self):
        docs = []

        for i in range(100):
            docs.append(create_vulnerability(create_asset(F'10.10.10.{i}', save=False), self.cve, save=False).to_dict())

        for i in range(100):
            vuln = create_vulnerability(create_asset(F'10.10.10.{i}', save=False), self.cve, save=False)
            vuln.tags.append(VulnerabilityStatus.FIXED)
            docs.append(vuln.to_dict())

        for i in range(100):
            asset = create_asset(F'10.10.10.{i}', save=False)
            asset.tags = [AssetStatus.DELETED]
            vuln = create_vulnerability(asset, self.cve, save=False)
            docs.append(vuln.to_dict())

        bulk(get_connection(), docs, refresh=True, index=VulnerabilityDocument.Index.name)

    def test_get_vulnerability_count(self):
        self.generate_vulns()
        tasks.prepare(VulnerabilityDocument.Index.name)
        self.assertEqual(tasks.get_cve_count(VulnerabilityDocument.Index.name, self.cve.id), 100)

    def test_start_processing_per_tenant(self):
        self.generate_assets()
        self.generate_vulns()

        vuln_search = VulnerabilityDocument.search()

        self.assertEqual(vuln_search.count(), 300)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_v2').count(), 0)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_vector_v2').count(), 0)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_v3').count(), 0)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_vector_v3').count(), 0)

        tasks._processing(0, 1, 1000, VulnerabilityDocument.Index.name)

        self.assertEqual(vuln_search.count(), 300)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_v2').count(), 100)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_vector_v2').count(), 100)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_v3').count(), 100)
        self.assertEqual(vuln_search.filter('exists', field='environmental_score_vector_v3').count(), 100)
