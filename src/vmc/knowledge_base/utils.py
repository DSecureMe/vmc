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


def impact_v2(cve: Cve) -> float:
    return 10.41 * (1 - (1 - cve.get_confidentiality_impact_v2_value()) *
                    (1 - cve.get_integrity_impact_v2_value()) *
                    (1 - cve.get_availability_impact_v2_value()))


def exploitability_v2(cve: Cve) -> float:
    return 20 * cve.get_access_vector_v2_value() * \
           cve.get_access_complexity_v2_value() * \
           cve.get_authentication_v2_value()


def f_impact_v2(imp: float) -> float:
    return 0 if imp == 0 else 1.176


def calculate_base_score_v2(cve: Cve) -> float:
    return round(((0.6 * impact_v2(cve)) + (0.4 * exploitability_v2(cve)) - 1.5) * f_impact_v2(impact_v2(cve)), 1)


def impact_sub_score_base_v3(cve: Cve) -> float:
    return 1 - (
            (1 - cve.get_confidentiality_impact_v3_value()) *
            (1 - cve.get_integrity_impact_v3_value()) *
            (1 - cve.get_availability_impact_v3_value())
    )


def impact_sub_score_v3(cve: Cve) -> float:
    isc_base = impact_sub_score_base_v3(cve)
    if ScopeV3(cve.scope_v3) == ScopeV3.UNCHANGED:
        return 6.42 * isc_base

    return 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)


def exploitability_v3(cve: Cve) -> float:
    return 8.22 * \
           cve.get_attack_vector_v3_value() * \
           cve.get_attack_complexity_v3_value() * \
           cve.get_privileges_required_v3_value() * \
           cve.get_user_interaction_v3_value()


def calculate_base_score_v3(cve: Cve) -> float:
    isc = impact_sub_score_v3(cve)
    exploitability = exploitability_v3(cve)

    if isc <= 0:
        return 0

    if ScopeV3(cve.scope_v3) == ScopeV3.UNCHANGED:
        base = min(isc + exploitability, 10)
    else:
        base = min(1.08 * (isc + exploitability), 10)

    return float(decimal.Decimal(base).quantize(decimal.Decimal('0.1'), rounding=decimal.ROUND_UP))
