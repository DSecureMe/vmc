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

from vmc.assets.models import Asset, Port
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
            'access_vector_v2': fields.KeywordField(),
            'access_complexity_v2': fields.KeywordField(),
            'authentication_v2': fields.KeywordField(),
            'confidentiality_impact_v2': fields.KeywordField(),
            'integrity_impact_v2': fields.KeywordField(),
            'availability_impact_v2': fields.KeywordField(),
            'attack_vector_v3': fields.KeywordField(),
            'attack_complexity_v3': fields.KeywordField(),
            'privileges_required_v3': fields.KeywordField(),
            'user_interaction_v3': fields.KeywordField(),
            'scope_v3': fields.KeywordField(),
            'confidentiality_impact_v3': fields.KeywordField(),
            'integrity_impact_v3': fields.KeywordField(),
            'availability_impact_v3': fields.KeywordField()
        }
    )

    asset = fields.ObjectField(
        properties={
            'ip_address': fields.KeywordField(),
            'mac_address': fields.KeywordField(),
            'os': fields.KeywordField(),
            'confidentiality_requirement': fields.KeywordField(),
            'integrity_requirement': fields.KeywordField(),
            'availability_requirement': fields.KeywordField()
        }
    )

    port = fields.ObjectField(
        properties={
            'number': fields.KeywordField(),
            'svc_name': fields.KeywordField(),
            'protocol': fields.KeywordField()
        }
    )

    environmental_score_v2 = fields.FloatField()
    environmental_score_v3 = fields.FloatField()

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
            Port,
            Cve
        ]

    def get_queryset(self):
        return super(VulnerabilityDocument, self).get_queryset().select_related(
            'asset', 'cve', 'port'
        )

    @staticmethod
    def get_instances_from_related(related_instance):
        if isinstance(related_instance, (Asset, Cve, Port)):
            return related_instance.vulnerability_set.all()
        return related_instance.vulenrability

    @staticmethod
    def prepare_environmental_score_v2(o):
        return environmental_score_v2(o.cve, o.asset)

    @staticmethod
    def prepare_environmental_score_v3(o):
        return environmental_score_v3(o.cve, o.asset) if o.cve.base_score_v3 else 0.0
