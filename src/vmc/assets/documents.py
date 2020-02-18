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
from decimal import Decimal

from elasticsearch_dsl import Keyword, InnerDoc, Q, Nested
from vmc.common.enum import TupleValueEnum

from vmc.common.elastic.documents import Document, TupleValueField
from vmc.common.elastic.registers import registry


class Impact(TupleValueEnum):
    LOW = ('L', Decimal('0.5'))
    MEDIUM = ('M', Decimal('1.0'))
    HIGH = ('H', Decimal('1.51'))
    NOT_DEFINED = ('N', Decimal('1.0'))


class OwnerInnerDoc(InnerDoc):
    name = Keyword()
    email = Keyword()
    department = Keyword()
    team = Keyword()


class AssetInnerDoc(InnerDoc):
    ip_address = Keyword()
    mac_address = Keyword()
    os = Keyword()
    cmdb_id = Keyword()
    confidentiality_requirement = TupleValueField(choice_type=Impact)
    integrity_requirement = TupleValueField(choice_type=Impact)
    availability_requirement = TupleValueField(choice_type=Impact)
    business_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    technical_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    hostname = Keyword()
    change_reason = Keyword()
    tags = Keyword()


@registry.register_document
class AssetDocument(Document, AssetInnerDoc):
    class Index:
        name = 'asset'

    @staticmethod
    def create_or_update(_: str, assets: dict) -> None:
        # TODO: paging
        total = AssetDocument.search().count()
        for current_assets in AssetDocument.search()[0:total]:
            key = current_assets.key()
            if key in assets:
                if current_assets.has_changed(assets[key]):
                    current_assets.update(assets[key], refresh=True)
                del assets[key]
            elif key not in assets and 'DELETED' not in current_assets.tags:
                current_assets.tags.append('DELETED')
                current_assets.save(refresh=True)
        for asset in assets.values():
            asset.save(refresh=True)

    def key(self):
        return '{}-{}'.format(self.cmdb_id, self.ip_address)
