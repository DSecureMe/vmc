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
from vmc.elasticsearch import Document, TupleValueField, Keyword, InnerDoc, Nested, Q, ListField
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
    confidentiality_requirement = TupleValueField(choice_type=Impact, default=Impact.NOT_DEFINED)
    integrity_requirement = TupleValueField(choice_type=Impact, default=Impact.NOT_DEFINED)
    availability_requirement = TupleValueField(choice_type=Impact, default=Impact.NOT_DEFINED)
    business_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    technical_owner = Nested(OwnerInnerDoc, include_in_parent=True)
    hostname = Keyword()
    change_reason = Keyword()
    tags = ListField()
    url = Keyword()


@registry.register_document
class AssetDocument(Document, AssetInnerDoc):
    class Index:
        name = 'asset'
        tenant_separation = True

    @staticmethod
    def create_or_update(assets: dict, config=None) -> None:
        index = AssetDocument.get_index(config)
        assets = AssetDocument._update_existing_assets(assets, index)
        assets = AssetDocument._update_discovered_assets(assets, index)

        for asset in assets.values():
            asset.save(refresh=True, index=index)

    @staticmethod
    def _update_existing_assets(assets: dict, index):
        if assets:
            assets_search = AssetDocument.search(index=index).filter(~Q('match', tags='DISCOVERED'))
            for st, en in AssetDocument._create_paging_steps(assets_search.count()):
                for current_asset in assets_search[st:en]:
                    asset_id = current_asset.id
                    if asset_id in assets:
                        if current_asset.has_changed(assets[asset_id]):
                            current_asset.update(assets[asset_id], refresh=True, index=index)
                        del assets[asset_id]
                    elif asset_id not in assets and 'DELETED' not in current_asset.tags:
                        current_asset.tags.append('DELETED')
                        current_asset.save(refresh=True, index=index)
        return assets

    @staticmethod
    def _update_discovered_assets(assets: dict, index):
        if assets:
            assets = {a.ip_address: a for a in assets.values()}
            assets_search = AssetDocument.search(index=index).filter(Q('match', tags='DISCOVERED'))
            for st, en in AssetDocument._create_paging_steps(assets_search.count()):

                for discovered_asset in assets_search[st:en]:
                    if discovered_asset.ip_address in assets:
                        discovered_asset.update(assets[discovered_asset.ip_address], refresh=True, index=index)
                        del assets[discovered_asset.ip_address]

        return assets

    @staticmethod
    def _create_paging_steps(total):
        step, start = 500, 0
        return [(start if i == start else i + 1, i + step) for i in range(0, total, step)]

    @staticmethod
    def get_or_create(ip_address, config=None):
        index = AssetDocument.get_index(config)
        result = AssetDocument.search(index=index).filter(
            Q('term', ip_address=ip_address) & ~Q('match', tags='DELETED')).execute()
        if result.hits:
            return result.hits[0]
        return AssetDocument(id=ip_address, ip_address=ip_address, tags=["DISCOVERED"]).save(index=index, refresh=True)
