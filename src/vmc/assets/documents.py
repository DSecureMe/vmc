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
from vmc.elasticsearch import Document, TupleValueField, Keyword, InnerDoc, Nested, Q, ListField, Date
from vmc.elasticsearch.registries import registry
from vmc.elasticsearch.helpers import async_bulk


class Impact(TupleValueEnum):
    LOW = ('L', Decimal('0.5'))
    MEDIUM = ('M', Decimal('1.0'))
    HIGH = ('H', Decimal('1.51'))
    NOT_DEFINED = ('ND', Decimal('1.0'))


class OwnerInnerDoc(InnerDoc):
    name = Keyword()
    email = Keyword()
    department = Keyword()
    team = Keyword()


class AssetStatus:
    DISCOVERED = 'DISCOVERED'
    DELETED = 'DELETED'


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
    service = Keyword()
    environment = Keyword()
    hostname = Keyword()
    tenant = Keyword()
    tags = ListField()
    url = Keyword()
    source = Keyword()
    last_scan_date = Date()


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

        async_bulk(list(map(lambda x: x.save(weak=True).to_dict(), assets.values())), index)

    @staticmethod
    def _update_existing_assets(assets: dict, index):
        if assets:
            updated = []
            assets_search = AssetDocument.search(index=index).filter(~Q('match', tags=AssetStatus.DISCOVERED))
            current_assets = [a for a in assets_search.scan()]
            for current_asset in current_assets:
                asset_id = current_asset.id
                if asset_id in assets:
                    if current_asset.has_changed(assets[asset_id]):
                        current_asset.update(assets[asset_id], index=index, weak=True)
                        updated.append(current_asset.to_dict(include_meta=True))
                    del assets[asset_id]
                elif asset_id not in assets and AssetStatus.DELETED not in current_asset.tags:
                    current_asset.tags.append(AssetStatus.DELETED)
                    updated.append(current_asset.save(index=index, weak=True).to_dict(include_meta=True))

                if len(updated) > 500:
                    async_bulk(updated)
                    updated = []

            async_bulk(updated)

        return assets

    @staticmethod
    def _update_discovered_assets(assets: dict, index):
        if assets:
            updated = []
            assets = {a.ip_address: a for a in assets.values()}
            assets_search = AssetDocument.search(index=index).filter(Q('match', tags=AssetStatus.DISCOVERED))
            discovered_assets = [a for a in assets_search.scan()]
            for discovered_asset in discovered_assets:
                if discovered_asset.ip_address in assets:
                    discovered_asset.update(assets[discovered_asset.ip_address], index=index, weak=True)
                    updated.append(discovered_asset.to_dict(include_meta=True))
                    del assets[discovered_asset.ip_address]
            if len(updated) > 500:
                async_bulk(updated)
                updated = []

            async_bulk(updated)

        return assets

    @staticmethod
    def get_or_create(ip_address, mac_address=None, config=None):
        index = AssetDocument.get_index(config)
        result = AssetDocument.search(index=index).filter(
            Q('term', ip_address=ip_address) & ~Q('match', tags=AssetStatus.DELETED)).execute()
        if result:
            return result[0]

        if hasattr(config, 'scanner'):
            source = config.scanner.split('.')[-1].capitalize()
        else:
            source = 'vmc'

        return AssetDocument(id=ip_address,
                             ip_address=ip_address,
                             mac_address=mac_address,
                             tenant=config.tenant.name if config and config.tenant else None,
                             source=source,
                             tags=[AssetStatus.DISCOVERED]).save(index=index, refresh=True)

    @staticmethod
    def get_assets_with_tag(tag: str, config=None):
        index = AssetDocument.get_index(config)
        result = AssetDocument.search(index=index).filter(
            Q("match", tags=tag))
        return result

    @staticmethod
    def update_gone_discovered_assets(targets, scanned_hosts, discovered_assets, config=None):
        index = AssetDocument.get_index(config)
        # FIXME: update by query
        scanned_ips = [x.ip_address for x in scanned_hosts]

        for asset in discovered_assets.scan():
            if asset.ip_address in targets and asset.ip_address not in scanned_ips:
                asset.tags.append(AssetStatus.DELETED)
                asset.save(index=index)

        async_bulk(list(map(lambda x: x.save(weak=True).to_dict(include_meta=True), scanned_hosts)), index)
