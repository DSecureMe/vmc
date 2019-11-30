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

from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry
from vmc.knowledge_base.models import Cve, Cpe, Cwe, Exploit


@registry.register_document
class CveDocument(Document):
    id = fields.KeywordField()
    base_score_v2 = fields.IntegerField()
    base_score_v3 = fields.IntegerField()
    summary = fields.KeywordField()
    exploits = fields.IntegerField()
    access_vector_v2 = fields.KeywordField()
    access_complexity_v2 = fields.KeywordField()
    authentication_v2 = fields.KeywordField()
    confidentiality_impact_v2 = fields.KeywordField()
    integrity_impact_v2 = fields.KeywordField()
    availability_impact_v2 = fields.KeywordField()
    attack_vector_v3 = fields.KeywordField()
    attack_complexity_v3 = fields.KeywordField()
    privileges_required_v3 = fields.KeywordField()
    user_interaction_v3 = fields.KeywordField()
    scope_v3 = fields.KeywordField()
    confidentiality_impact_v3 = fields.KeywordField()
    integrity_impact_v3 = fields.KeywordField()
    availability_impact_v3 = fields.KeywordField()
    published_date = fields.DateField()
    last_modified_date = fields.DateField()

    cwe = fields.ObjectField(
        properties={
            'id': fields.KeywordField(),
            'name': fields.KeywordField(),
            'description': fields.KeywordField()
        }
    )

    cpe = fields.ObjectField(
        properties={
            'vendor': fields.KeywordField(),
            'name': fields.KeywordField(),
        }
    )

    class Index:
        name = 'cve'

    class Django:
        model = Cve
        related_models = [Cwe, Cpe, Exploit]

    @staticmethod
    def prepare_exploits(instance):
        return instance.exploits.count()

    @staticmethod
    def prepare_access_vector_v2(instance):
        return instance.get_access_vector_v2_display()

    @staticmethod
    def prepare_access_complexity_v2(instance):
        return instance.get_access_complexity_v2_display()

    @staticmethod
    def prepare_authentication_v2(instance):
        return instance.get_authentication_v2_display()

    @staticmethod
    def prepare_confidentiality_impact_v2(instance):
        return instance.get_confidentiality_impact_v2_display()

    @staticmethod
    def prepare_integrity_impact_v2(instance):
        return instance.get_integrity_impact_v2_display()

    @staticmethod
    def prepare_availability_impact_v2(instance):
        return instance.get_availability_impact_v2_display()

    @staticmethod
    def prepare_attack_vector_v3(instance):
        return instance.get_attack_vector_v3_display()

    @staticmethod
    def prepare_attack_complexity_v3(instance):
        return instance.get_attack_complexity_v3_display()

    @staticmethod
    def prepare_privileges_required_v3(instance):
        return instance.get_privileges_required_v3_display()

    @staticmethod
    def prepare_user_interaction_v3(instance):
        return instance.get_user_interaction_v3_display()

    @staticmethod
    def prepare_scope_v3(instance):
        return instance.get_scope_v3_display()

    @staticmethod
    def prepare_confidentiality_impact_v3(instance):
        return instance.get_confidentiality_impact_v3_display()

    @staticmethod
    def prepare_integrity_impact_v3(instance):
        return instance.get_integrity_impact_v3_display()

    @staticmethod
    def prepare_availability_impact_v3(instance):
        return instance.get_availability_impact_v3_display()

    def get_queryset(self):
        return super(CveDocument, self).get_queryset().select_related(
            'cwe',
        )

    @staticmethod
    def get_instances_from_related(related_instance):
        if isinstance(related_instance, (Cwe, Cpe, Exploit)):
            return related_instance.cve_set.all()
        return None


@registry.register_document
class CweDocument(Document):
    id = fields.KeywordField()
    name = fields.KeywordField()
    status = fields.KeywordField()
    weakness_abstraction = fields.KeywordField()
    description = fields.KeywordField()
    extended_description = fields.KeywordField()

    class Index:
        name = 'cwe'

    class Django:
        model = Cwe


@registry.register_document
class ExploitDocument(Document):
    id = fields.KeywordField()

    class Index:
        name = 'exploit'

    class Django:
        model = Exploit
