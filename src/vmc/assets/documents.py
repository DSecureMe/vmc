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

from vmc.common.enum import TupleValueEnum
from vmc.elasticsearch import Document, TupleValueField, Keyword, InnerDoc, Nested, Q
from vmc.elasticsearch.registries import registry


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
    id = Keyword()
    ip_address = Keyword()
    mac_address = Keyword()
    os = Keyword()
    confidentiality_requirement = TupleValueField(choice_type=Impact)
    integrity_requirement = TupleValueField(choice_type=Impact)
    availability_requirement = TupleValueField(choice_type=Impact)
    business_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    technical_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    hostname = Keyword()
    change_reason = Keyword()
    tags = Keyword()
    url = Keyword()


@registry.register_document
class AssetDocument(Document, AssetInnerDoc):
    class Index:
        name = 'assets'

    @staticmethod
    def create_or_update(tag: str, assets: dict, index=None) -> None:
        # TODO: paging
        total = AssetDocument.search(index=index).filter(Q('match', tags=tag)).count()
        for current_assets in AssetDocument.search().filter(Q('match', tags=tag))[0:total]:
            asset_id = current_assets.id
            if current_assets.id in assets:
                if current_assets.has_changed(assets[asset_id]):
                    current_assets.update(assets[asset_id], refresh=True)
                del assets[asset_id]
            elif asset_id not in assets and 'DELETED' not in current_assets.tags:
                current_assets.tags.append('DELETED')
                current_assets.save(refresh=True, index=index)
        for asset in assets.values():
            asset.save(refresh=True, index=index)
