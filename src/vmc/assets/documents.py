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

from django_elasticsearch_dsl.registries import registry
from django_elasticsearch_dsl import Document, fields

from vmc.assets.models import Asset


@registry.register_document
class AssetDocument(Document):
    ip_address = fields.KeywordField()
    os = fields.KeywordField()
    confidentiality_requirement = fields.KeywordField()
    integrity_requirement = fields.KeywordField()
    availability_requirement = fields.KeywordField()

    class Index:
        name = 'asset'

    class Django:
        model = Asset

    @staticmethod
    def prepare_confidentiality_requirement(instance) -> str:
        return instance.get_confidentiality_requirement_display()

    @staticmethod
    def prepare_integrity_requirement(instance) -> str:
        return instance.get_integrity_requirement_display()

    @staticmethod
    def prepare_availability_requirement(instance) -> str:
        return instance.get_availability_requirement_display()
