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
import logging
import uuid

from vmc.ralph.models import Config
from vmc.assets.documents import AssetDocument, OwnerInnerDoc, Impact

LOGGER = logging.getLogger(__name__)


class OwnerParser:

    @staticmethod
    def parse(users: list) -> dict:
        result = dict()
        for user in users:
            try:
                result[user['id']] = OwnerInnerDoc(
                    name='{first} {last} ({username})'.format(
                        first=user['first_name'],
                        last=user['last_name'],
                        username=user['username']),
                    email=user['email'],
                    department=user['department'] if user['department'] else '',
                    team=user['team']['name'] if user['team'] else '')
            except KeyError as ex:
                LOGGER.warning(ex)
        return result


class AssetsParser:

    def __init__(self, config: Config):
        self.__config = config
        self.__parsed = dict()
        self.__users = dict()

    def parse(self, assets: list, users: dict = None) -> dict:
        if users:
            self.__users = users

        for asset in assets:
            try:
                for iface in asset['ethernet']:
                    self.create(asset, iface)
            except TypeError:
                pass
        return self.__parsed

    def create(self, item: dict, iface: dict):
        asset = AssetDocument()
        asset.tags = [self.__config.name]
        for field in AssetDocument.get_fields_name():
            parser = getattr(self, field, None)
            try:
                if parser:
                    setattr(asset, field, parser(item, iface))
            except (KeyError, IndexError):
                setattr(asset, field, 'UNKNOWN')
        self.__parsed[asset.id] = asset

    def id(self, _, iface: dict) -> str:
        key = '{}-{}-{}'.format(self.__config.pk, iface['id'], AssetsParser.ip_address(_, iface))
        return str(uuid.uuid3(uuid.NAMESPACE_OID, key))

    @staticmethod
    def ip_address(_, iface: dict) -> str:
        return iface['ipaddress']['address']

    @staticmethod
    def environment(item: dict, _) -> str:
        return item['service_env']['environment']

    @staticmethod
    def service(item: dict, _) -> str:
        return item['service_env']['service']

    @staticmethod
    def mac_address(_, iface: dict) -> str:
        return iface['mac']

    @staticmethod
    def os(item: dict, _) -> str:
        return item['custom_fields']['os']

    def business_owner(self, item: dict, _) -> list:
        return self.owner(item, 'business_owners')

    def technical_owner(self, item: dict, _) -> list:
        return self.owner(item, 'technical_owners')

    def owner(self, item: dict, field_name: str) -> list:
        owners = [self.__users[us['id']] for us in item[field_name] if us['id'] in self.__users]
        return owners if owners else [OwnerInnerDoc()]

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

    def url(self, item: dict, _) -> str:
        return '{}/data_center/datacenterasset/{}'.format(self.__config.get_url(), item['id'])
