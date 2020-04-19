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
from __future__ import absolute_import, unicode_literals

import logging
import decimal

from celery import shared_task
from django.core.cache import cache
from elasticsearch.helpers import bulk
from elasticsearch_dsl.connections import get_connection


from vmc.knowledge_base.metrics import ScopeV3
from vmc.knowledge_base.utils import exploitability_v2, impact_v2, f_impact_v2
from vmc.common.tasks import memcache_lock
from vmc.elasticsearch.models import Tenant
from vmc.elasticsearch.registries import DocumentRegistry
from vmc.elasticsearch import Q
from vmc.assets.documents import AssetDocument, Impact, AssetStatus
from vmc.vulnerabilities.documents import VulnerabilityDocument, VulnerabilityStatus

LOGGER = logging.getLogger(__name__)

TARGET_DISTRIBUTION_NOT_DEFINED_V2 = 1.00
TARGET_DISTRIBUTION_LOW_V2 = 0.25
TARGET_DISTRIBUTION_MEDIUM_V2 = 0.75
TARGET_DISTRIBUTION_HIGH_V2 = 1.00
TARGET_DISTRIBUTION_NONE_V2 = 0.00

TEMPORAL_REMEDIATION_LEVEL_NOT_DEFINED_V2 = 1.00
TEMPORAL_REPORT_CONFIDENCE_NOT_DEFINED_V2 = 1.00
TEMPORAL_EXPLOITABILITY_NOT_DEFINED_V2 = 1.00

EXPLOIT_CODE_MATURITY_NOT_DEFINED_V3 = 1.0
REMEDIATION_LEVEL_NOT_DEFINED_V3 = 1.0
REPORT_CONFIDENCE_NOT_DEFINED_V3 = 1.0

COLLATERAL_DAMAGE_POTENTIAL_NONE_V2 = 0.0
COLLATERAL_DAMAGE_POTENTIAL_LOW_V2 = 0.1
COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2 = 0.3
COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2 = 0.4
COLLATERAL_DAMAGE_POTENTIAL_HIGH_V2 = 0.5
COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2 = 0.0


def collateral_damage_potential_v2(asset) -> float:
    req = [asset.confidentiality_requirement, asset.integrity_requirement, asset.availability_requirement]

    if req.count(Impact.HIGH) == 3:
        return COLLATERAL_DAMAGE_POTENTIAL_HIGH_V2

    if req.count(Impact.HIGH) > 0:
        return COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH_V2

    if req.count(Impact.MEDIUM) > 0:
        return COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM_V2

    if req.count(Impact.LOW) > 1:
        return COLLATERAL_DAMAGE_POTENTIAL_LOW_V2

    return COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED_V2


def target_distribution_v2(vuln_count, assets_count) -> float:
    distribution = round(vuln_count / assets_count, 3)

    if distribution < 0.01:
        return TARGET_DISTRIBUTION_NONE_V2

    if 0.01 <= distribution <= TARGET_DISTRIBUTION_LOW_V2:
        return TARGET_DISTRIBUTION_LOW_V2

    if TARGET_DISTRIBUTION_LOW_V2 < distribution <= TARGET_DISTRIBUTION_MEDIUM_V2:
        return TARGET_DISTRIBUTION_MEDIUM_V2

    if TARGET_DISTRIBUTION_MEDIUM_V2 < distribution <= TARGET_DISTRIBUTION_HIGH_V2:
        return TARGET_DISTRIBUTION_HIGH_V2

    return TARGET_DISTRIBUTION_NOT_DEFINED_V2


def adjusted_impact_v2(cve, asset) -> float:
    return min(10, 10.41 *
               (1 - (1 - cve.confidentiality_impact_v2.second_value * asset.confidentiality_requirement.second_value) *
                (1 - cve.integrity_impact_v2.second_value * asset.integrity_requirement.second_value) *
                (1 - cve.availability_impact_v2.second_value * asset.availability_requirement.second_value)))


def adjusted_base_v2(cve, asset) -> float:
    ai = adjusted_impact_v2(cve, asset)
    return round(((0.6 * ai) + (0.4 * exploitability_v2(cve)) - 1.5) * f_impact_v2(impact_v2(cve)), 1)


def temporal_remediation_level_v2() -> float:
    return TEMPORAL_REMEDIATION_LEVEL_NOT_DEFINED_V2


def temporal_report_confidence_v2() -> float:
    return TEMPORAL_REPORT_CONFIDENCE_NOT_DEFINED_V2


def temporal_exploitability_v2() -> float:
    return TEMPORAL_EXPLOITABILITY_NOT_DEFINED_V2


def adjusted_temporal_score_v2(cve, asset) -> float:
    return round(adjusted_base_v2(cve, asset) *
                 temporal_exploitability_v2() *
                 temporal_remediation_level_v2() *
                 temporal_report_confidence_v2(), 1)


def calculate_environmental_score_v2(vuln, vuln_count, assets_count):
    if vuln.cve.base_score_v2:
        at = adjusted_temporal_score_v2(vuln.cve, vuln.asset)
        cdp = collateral_damage_potential_v2(vuln.asset)
        tg = target_distribution_v2(vuln_count, assets_count)
        return round((at + (10 - at) * cdp) * tg, 1)

    return 0.0


def exploitability_v3(cve) -> float:
    return 8.22 * \
           cve.attack_vector_v3.second_value * \
           cve.attack_complexity_v3.second_value * \
           cve.get_privileges_required_v3_value() * \
           cve.user_interaction_v3.second_value


def impact_sub_score_base_v3(cve, asset) -> float:
    return min((1 - (1 - cve.confidentiality_impact_v3.second_value * asset.confidentiality_requirement.second_value) *
                (1 - cve.integrity_impact_v3.second_value * asset.integrity_requirement.second_value) *
                (1 - cve.availability_impact_v3.second_value * asset.availability_requirement.second_value)), 0.915)


def impact_sub_score_v3(cve, asset) -> float:
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


def calculate_environmental_score_v3(vuln) -> float:
    if vuln.cve.base_score_v3:
        isc = impact_sub_score_v3(vuln.cve, vuln.asset)
        exploitability = exploitability_v3(vuln.cve)

        if isc <= 0:
            return 0

        if ScopeV3(vuln.cve.scope_v3) == ScopeV3.UNCHANGED:
            score = isc + exploitability
        else:
            score = 1.08 * (isc + exploitability)

        return float(decimal.Decimal(min(score, 10) *
                                     exploit_code_maturity_v3() *
                                     remediation_level_v3() *
                                     report_confidence_v3())
                     .quantize(decimal.Decimal('0.1'), rounding=decimal.ROUND_UP))
    return 0.0


def get_vulnerability_count(cve_id, vulnerability_index):
    key = F'{cve_id}-{vulnerability_index}'
    count = cache.get(key, None, 60)
    if not count:
        s = VulnerabilityDocument.search(index=vulnerability_index).filter(
            Q('match', cve__id=cve_id) &
            ~Q('match', tags=VulnerabilityStatus.FIXED) &
            ~Q('match', asset__tags=AssetStatus.DELETED)
        )
        s.aggs.metric('by_ip', 'cardinality', field='asset.ip_address')
        s = s.execute()
        count = s.aggregations.by_ip.value
        cache.add(key, count, 60)
    return count


def _start_processing_per_tenant(vulnerability_index: str, asset_index: str):
    docs = []

    assets_count = AssetDocument.search(
        index=asset_index).filter(~Q('match', tags=AssetStatus.DELETED)).count()
    vuln_search = VulnerabilityDocument.search(
        index=vulnerability_index).filter(
        ~Q('match', tags=VulnerabilityStatus.FIXED) &
        ~Q('match', asset__tags=AssetStatus.DELETED)
    )

    for vuln in vuln_search.scan():
        vuln_count = get_vulnerability_count(vuln.cve.id, vulnerability_index)
        vuln.environmental_score_v3 = calculate_environmental_score_v3(vuln)
        vuln.environmental_score_v2 = calculate_environmental_score_v2(vuln, vuln_count, assets_count)
        docs.append(vuln.to_dict(include_meta=True))

    if docs:
        bulk(get_connection(), docs, refresh=True, index=vulnerability_index)


@shared_task(ignore_result=True)
def start_processing_per_tenant(vulnerability_index: str, asset_index: str):
    lock_id = F'update-environmental-loc-{vulnerability_index}-{asset_index}'
    with memcache_lock(lock_id, lock_id) as acquired:
        if acquired:
            return _start_processing_per_tenant(vulnerability_index, asset_index)
    LOGGER.info(
        F'Update environmental for {vulnerability_index} and {asset_index} are already being done by another worker')
    return False


@shared_task(ignore_result=True)
def start_processing():
    tenants = Tenant.objects.all()

    for tenant in tenants:
        vulnerability_index = DocumentRegistry.get_index_for_tenant(tenant, VulnerabilityDocument)
        asset_index = DocumentRegistry.get_index_for_tenant(tenant, AssetDocument)
        start_processing_per_tenant.delay(
            vulnerability_index=vulnerability_index,
            asset_index=asset_index
        )

    start_processing_per_tenant.delay(
        vulnerability_index=VulnerabilityDocument.Index.name,
        asset_index=AssetDocument.Index.name
    )
