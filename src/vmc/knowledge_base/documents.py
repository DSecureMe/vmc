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

from vmc.knowledge_base import metrics
from vmc.elasticsearch import Document, TupleValueField, EnumField
from vmc.elasticsearch import InnerDoc, Date, Keyword, Float, Nested, Object
from vmc.elasticsearch.registries import registry


class ExploitInnerDoc(InnerDoc):
    id = Keyword()
    url = Keyword()

    @staticmethod
    def create(exp_id: int):
        url = F'https://www.exploit-db.com/exploits/{exp_id}'
        return ExploitInnerDoc(id=exp_id, url=url)


class CpeInnerDoc(InnerDoc):
    name = Keyword()
    vendor = Keyword()


class CweInnerDoc(InnerDoc):
    id = Keyword()
    name = Keyword()
    status = Keyword()
    weakness_abstraction = Keyword()
    description = Keyword()
    extended_description = Keyword()


class CveInnerDoc(InnerDoc):
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

    exploits = Nested(ExploitInnerDoc, include_in_parent=True)
    cpe = Nested(CpeInnerDoc, include_in_parent=True)
    cwe = Object(CweInnerDoc, include_in_parent=True)

    def get_privileges_required_v3_value(self) -> float:
        scope = metrics.ScopeV3(self.scope_v3)
        return float(metrics.PrivilegesRequiredV3(self.privileges_required_v3).value_with_scope(scope))


@registry.register_document
class CweDocument(CweInnerDoc, Document):
    class Index:
        name = 'cwe'


@registry.register_document
class CveDocument(CveInnerDoc, Document):
    class Index:
        name = 'cve'
        related_documents = [CweDocument]

    @staticmethod
    def get_or_create(cve_id: str):
        result = CveDocument.search().filter('term', id=cve_id).execute()
        if result.hits:
            return result.hits[0]
        cve = CveDocument(id=cve_id)
        return cve.save(refresh=True)
