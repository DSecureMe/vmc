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

from vmc.assets.models import Asset
from vmc.knowledge_base.models import Cve
from vmc.vulnerabilities.models import Vulnerability
from vmc.vulnerabilities.utils import environmental_score_v2, environmental_score_v3


@registry.register_document
class VulnerabilityDocument(Document):
    cve = fields.ObjectField(
        properties={
            'id': fields.KeywordField(),
            'base_score_v2': fields.FloatField(),
            'base_score_v3': fields.FloatField(),
            'summary': fields.KeywordField(),
            'published_date': fields.KeywordField(),
            'last_modified_date': fields.KeywordField(),
            'access_vector_v2': fields.KeywordField(attr='get_access_vector_v2_display'),
            'access_complexity_v2': fields.KeywordField(attr='get_access_complexity_v2_display'),
            'authentication_v2': fields.KeywordField(attr='get_authentication_v2_display'),
            'confidentiality_impact_v2': fields.KeywordField(attr='get_confidentiality_impact_v2_display'),
            'integrity_impact_v2': fields.KeywordField(attr='get_integrity_impact_v2_display'),
            'availability_impact_v2': fields.KeywordField(attr='get_availability_impact_v2_display'),
            'attack_vector_v3': fields.KeywordField(attr='get_attack_vector_v3_display'),
            'attack_complexity_v3': fields.KeywordField(attr='get_attack_complexity_v3_display'),
            'privileges_required_v3': fields.KeywordField(attr='get_privileges_required_v3_display'),
            'user_interaction_v3': fields.KeywordField(attr='get_user_interaction_v3_display'),
            'scope_v3': fields.KeywordField(attr='get_scope_v3_display'),
            'confidentiality_impact_v3': fields.KeywordField(attr='get_confidentiality_impact_v3_display'),
            'integrity_impact_v3': fields.KeywordField(attr='get_integrity_impact_v3_display'),
            'availability_impact_v3': fields.KeywordField(attr='get_availability_impact_v3_display')
        }
    )

    asset = fields.ObjectField(
        properties={
            'ip_address': fields.KeywordField(),
            'mac_address': fields.KeywordField(),
            'os': fields.KeywordField(),
            'confidentiality_requirement': fields.KeywordField(attr='get_confidentiality_requirement_display'),
            'integrity_requirement': fields.KeywordField(attr='get_integrity_requirement_display'),
            'availability_requirement': fields.KeywordField(attr='get_availability_requirement_display')
        }
    )

    port = fields.KeywordField()
    svc_name = fields.KeywordField()
    protocol = fields.KeywordField()
    environmental_score_v2 = fields.FloatField()
    environmental_score_v3 = fields.FloatField()
    created_date = fields.DateField()
    modified_date = fields.DateField()

    class Index:
        name = 'vulnerability'

    class Django:
        model = Vulnerability
        fields = [
            'description',
            'solution',
            'exploit_available'
        ]
        related_models = [
            Asset,
            Cve
        ]

    def get_queryset(self):
        return super(VulnerabilityDocument, self).get_queryset().select_related(
            'asset', 'cve'
        )

    @staticmethod
    def get_instances_from_related(related_instance):
        if isinstance(related_instance, (Asset, Cve)):
            return related_instance.vulnerability_set.all()
        return related_instance.vulenrability

    @staticmethod
    def prepare_environmental_score_v2(o):
        return environmental_score_v2(o.cve, o.asset)

    @staticmethod
    def prepare_environmental_score_v3(o):
        return environmental_score_v3(o.cve, o.asset) if o.cve.base_score_v3 else 0.0
