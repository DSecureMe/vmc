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

from elasticsearch_dsl import Nested, Integer, Keyword, Object, Float, Date, InnerDoc

from vmc.assets.documents import Impact
from vmc.knowledge_base import metrics
from vmc.common.elastic.documents import TupleValueField

from vmc.common.elastic.documents import Document, EnumField
from vmc.common.elastic.registers import registry
from vmc.knowledge_base.documents import ExploitDocument, CpeDocument

from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


class CveDocument(InnerDoc):
    id = Keyword()
    base_score_v2 = Float()
    base_score_v3 = Float()
    summary = Keyword()
    access_vector_v2 = TupleValueField(choice_type=metrics.AccessVectorV2)
    access_complexity_v2 = TupleValueField(choice_type=metrics.AccessComplexityV2)
    authentication_v2 = TupleValueField(choice_type=metrics.AuthenticationV2)
    confidentiality_impact_v2 = TupleValueField(choice_type=metrics.ImpactV2)
    integrity_impact_v2 = TupleValueField(choice_type=metrics.ImpactV2)
    availability_impact_v2 = TupleValueField(choice_type=metrics.ImpactV2)
    attack_vector_v3 = TupleValueField(choice_type=metrics.AttackVectorV3)
    attack_complexity_v3 = TupleValueField(choice_type=metrics.AttackComplexityV3)
    privileges_required_v3 = EnumField(choice_type=metrics.PrivilegesRequiredV3)
    user_interaction_v3 = TupleValueField(choice_type=metrics.UserInteractionV3)
    scope_v3 = EnumField(choice_type=metrics.ScopeV3)
    confidentiality_impact_v3 = TupleValueField(choice_type=metrics.ImpactV3)
    integrity_impact_v3 = TupleValueField(choice_type=metrics.ImpactV3)
    availability_impact_v3 = TupleValueField(choice_type=metrics.ImpactV3)
    published_date = Date()
    last_modified_date = Date()

    exploits = Nested(ExploitDocument)
    cpe = Nested(CpeDocument)

    def get_privileges_required_v3_value(self) -> float:
        scope = metrics.ScopeV3(self.scope_v3)
        return float(metrics.PrivilegesRequiredV3(self.privileges_required_v3).value_with_scope(scope))


class AssetDocument(InnerDoc):
    ip_address = Keyword()
    os = Keyword()
    cmdb_id = Keyword()
    confidentiality_requirement = TupleValueField(choice_type=Impact)
    integrity_requirement = TupleValueField(choice_type=Impact)
    availability_requirement = TupleValueField(choice_type=Impact)
    business_owner = Keyword()
    technical_owner = Keyword()
    hostname = Keyword()
    created_date = Date()
    modified_date = Date()
    change_reason = Keyword()


@registry.register_document
class VulnerabilityDocument(Document):
    port = Integer()
    svc_name = Keyword()
    protocol = Keyword()
    description = Keyword()
    solution = Keyword()
    environmental_score_v2 = Float()
    environmental_score_v3 = Float()
    cve = Object(CveDocument)
    asset = Object(AssetDocument)

    class Index:
        name = 'vulnerability'

    def prepare_environmental_score_v2(self):
        return environmental_score_v2(self.cve, self.asset) if self.cve.base_score_v2 else 0.0

    def prepare_environmental_score_v3(self):
        return environmental_score_v3(self.cve, self.asset) if self.cve.base_score_v3 else 0.0

    def save(self, *args, **kwargs):
        self.environmental_score_v2 = self.prepare_environmental_score_v2()
        self.environmental_score_v3 = self.prepare_environmental_score_v3()
        return super().save(*args, **kwargs)
