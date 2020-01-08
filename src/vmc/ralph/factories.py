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
 */
"""
from vmc.assets.models import Asset, Impact


class AssetFactory:
    FIELD_LIST = [field.name for field in Asset._meta.get_fields() if field]
    IMPACT = {'LOW': 'L', 'MEDIUM': 'M', 'HIGH': 'H', 'NOT_DEFINED': 'N'}

    @staticmethod
    def process(item: dict) -> None:
        for iface in item['ethernet']:
            AssetFactory.create(item, iface)

    @staticmethod
    def create(item: dict, iface: dict) -> Asset:
        asset, _ = Asset.objects.get_or_create(
            cmdb_id=AssetFactory.cmdb_id(item, iface),
            ip_address=AssetFactory.ip_address(item, iface)
        )

        for field in sorted(AssetFactory.FIELD_LIST):
            parser = getattr(AssetFactory, field, None)
            try:
                if parser:
                    setattr(asset, field, parser(item, iface))
            except (KeyError, IndexError):
                setattr(asset, field, 'UNKNOWN')
        if asset.has_changed:
            asset.save()
        return asset

    @staticmethod
    def cmdb_id(item: dict, _) -> int:
        return item['id']

    @staticmethod
    def ip_address(_, iface: dict) -> str:
        return iface['ipaddress']['address']

    @staticmethod
    def mac_address(_, iface: dict) -> str:
        return iface['mac']

    @staticmethod
    def os(item: dict, _) -> str:
        return item['custom_fields']['os']

    @staticmethod
    def business_owner(item: dict, _) -> str:
        return item['business_owners'][0]['username']

    @staticmethod
    def technical_owner(item: dict, _) -> str:
        return item['technical_owners'][0]['username']

    @staticmethod
    def hostname(item: dict, _) -> str:
        return item['hostname']

    @staticmethod
    def confidentiality_requirement(item: dict, _) -> str:
        try:
            return AssetFactory.IMPACT[item['custom_fields']['confidentiality']]
        except KeyError:
            return Impact.NOT_DEFINED.value

    @staticmethod
    def integrity_requirement(item: dict, _) -> str:
        try:
            return AssetFactory.IMPACT[item['custom_fields']['integrity']]
        except KeyError:
            return Impact.NOT_DEFINED.value

    @staticmethod
    def availability_requirement(item: dict, _) -> str:
        try:
            return AssetFactory.IMPACT[item['custom_fields']['availability']]
        except KeyError:
            return Impact.NOT_DEFINED.value
