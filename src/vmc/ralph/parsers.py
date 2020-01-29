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

from vmc.assets.documents import AssetDocument, Impact


class AssetsParser:

    def __init__(self, config_name: str):
        self.__config_name = config_name
        self.__parsed = list()

    def parse(self, assets: list) -> list:
        for asset in assets:
            for iface in asset['ethernet']:
                self.create(asset, iface)
        return self.__parsed

    def create(self, item: dict, iface: dict):
        asset = AssetDocument()
        asset.tags = [self.__config_name]
        for field in AssetDocument.get_fields_name():
            parser = getattr(AssetsParser, field, None)
            try:
                if parser:
                    setattr(asset, field, parser(item, iface))
            except (KeyError, IndexError):
                setattr(asset, field, 'UNKNOWN')
        self.__parsed.append(asset)

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
        return AssetsParser.owner(item['business_owners'][0])

    @staticmethod
    def technical_owner(item: dict, _) -> str:
        return AssetsParser.owner(item['technical_owners'][0])

    @staticmethod
    def owner(item: dict) -> str:
        return '{first} {last} ({username})'.format(
            first=item['first_name'],
            last=item['last_name'],
            username=item['username']
        )

    @staticmethod
    def hostname(item: dict, _) -> str:
        return item['hostname']

    @staticmethod
    def confidentiality_requirement(item: dict, _) -> Impact:
        try:
            return Impact(item['custom_fields']['confidentiality'])
        except KeyError:
            return Impact.NOT_DEFINED

    @staticmethod
    def integrity_requirement(item: dict, _) -> Impact:
        try:
            return Impact(item['custom_fields']['integrity'])
        except KeyError:
            return Impact.NOT_DEFINED

    @staticmethod
    def availability_requirement(item: dict, _) -> Impact:
        try:
            return Impact(item['custom_fields']['availability'])
        except KeyError:
            return Impact.NOT_DEFINED
