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

import decimal

from vmc.knowledge_base.metrics import ScopeV3
from vmc.knowledge_base.models import Cve
from vmc.assets.models import Asset
from vmc.knowledge_base.utils import exploitability_v2, impact_v2, f_impact_v2

TARGET_DISTRIBUTION_NOT_DEFINED_V2 = 1.0
COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2 = 0.0
TEMPORAL_REMEDIATION_LEVEL_NOT_DEFINED_V2 = 1.00
TEMPORAL_REPORT_CONFIDENCE_NOT_DEFINED_V2 = 1.00
TEMPORAL_EXPLOITABILITY_NOT_DEFINED_V2 = 1.00

EXPLOIT_CODE_MATURITY_NOT_DEFINED_V3 = 1.0
REMEDIATION_LEVEL_NOT_DEFINED_V3 = 1.0
REPORT_CONFIDENCE_NOT_DEFINED_V3 = 1.0


def collateral_damage_potential_v2() -> float:
    return COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2


def target_distribution_v2() -> float:
    return TARGET_DISTRIBUTION_NOT_DEFINED_V2


def adjusted_impact_v2(cve: Cve, asset: Asset) -> float:
    return min(10, 10.41 *
               (1 - (1 - cve.get_confidentiality_impact_v2_value() * asset.get_confidentiality_requirement_value()) *
                (1 - cve.get_integrity_impact_v2_value() * asset.get_integrity_requirement_value()) *
                (1 - cve.get_availability_impact_v2_value() * asset.get_availability_requirement_value())))


def adjusted_base_v2(cve: Cve, asset: Asset) -> float:
    ai = adjusted_impact_v2(cve, asset)
    return round(((0.6 * ai) + (0.4 * exploitability_v2(cve)) - 1.5) * f_impact_v2(impact_v2(cve)), 1)


def temporal_remediation_level_v2() -> float:
    return TEMPORAL_REMEDIATION_LEVEL_NOT_DEFINED_V2


def temporal_report_confidence_v2() -> float:
    return TEMPORAL_REPORT_CONFIDENCE_NOT_DEFINED_V2


def temporal_exploitability_v2() -> float:
    return TEMPORAL_EXPLOITABILITY_NOT_DEFINED_V2


def adjusted_temporal_score_v2(cve: Cve, asset: Asset) -> float:
    return round(adjusted_base_v2(cve, asset) *
                 temporal_exploitability_v2() *
                 temporal_remediation_level_v2() *
                 temporal_report_confidence_v2(), 1)


def environmental_score_v2(cve: Cve, asset: Asset) -> float:
    at = adjusted_temporal_score_v2(cve, asset)
    return round((at + (10 - at) * collateral_damage_potential_v2()) * target_distribution_v2(), 1)


def exploitability_v3(cve: Cve) -> float:
    return 8.22 * \
           cve.get_attack_vector_v3_value() * \
           cve.get_attack_complexity_v3_value() * \
           cve.get_privileges_required_v3_value() * \
           cve.get_user_interaction_v3_value()


def impact_sub_score_base_v3(cve: Cve, asset: Asset) -> float:
    return min((1 - (1 - cve.get_confidentiality_impact_v3_value() * asset.get_confidentiality_requirement_value()) *
                (1 - cve.get_integrity_impact_v3_value() * asset.get_integrity_requirement_value()) *
                (1 - cve.get_availability_impact_v3_value() * asset.get_availability_requirement_value())), 0.915)


def impact_sub_score_v3(cve: Cve, asset: Asset) -> float:
    isc = impact_sub_score_base_v3(cve, asset)
    if ScopeV3(cve.scope_v3) == ScopeV3.UNCHANGED:
        return 6.42 * isc
    return 7.52 * (isc - 0.029) - 3.25 * pow(isc - 0.02, 15)


def exploit_code_maturity_v3() -> float:
    return EXPLOIT_CODE_MATURITY_NOT_DEFINED_V3


def remediation_level_v3() -> float:
    return REMEDIATION_LEVEL_NOT_DEFINED_V3


def report_confidence_v3() -> float:
    return REPORT_CONFIDENCE_NOT_DEFINED_V3


def environmental_score_v3(cve: Cve, asset: Asset) -> float:
    isc = impact_sub_score_v3(cve, asset)
    exploitability = exploitability_v3(cve)

    if isc <= 0:
        return 0

    if ScopeV3(cve.scope_v3) == ScopeV3.UNCHANGED:
        score = isc + exploitability
    else:
        score = 1.08 * (isc + exploitability)

    return float(decimal.Decimal(min(score, 10) *
                                 exploit_code_maturity_v3() *
                                 remediation_level_v3() *
                                 report_confidence_v3())
                 .quantize(decimal.Decimal('0.1'), rounding=decimal.ROUND_UP))
