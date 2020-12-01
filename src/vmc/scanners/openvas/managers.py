
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
import logging

from vmc.scanners.managers import Manager
from vmc.scanners.openvas.clients import OpenVasClient
from vmc.scanners.openvas.parsers import GmpParserOMP7, GMP9Parser

LOGGER = logging.getLogger(__name__)


class OpenVasManagerException(Exception):
    pass


class OpenVasManager(Manager):

    def __init__(self, config):
        self._config = config

    def get_client(self):
        return OpenVasClient(self._config)

    def get_parser(self):
        try:

            v = self.get_client().get_version()
            v = v.find('./version').text.strip()

            if v == '9.0':
                p = GMP9Parser(self._config)
            elif v == '7.0':
                p = GmpParserOMP7(self._config)
            else:
                LOGGER.error(F'Unknown openvas version {v}')
                raise Exception(F'Unknown openvas protocol version {v}')

            p.get_targets = self.get_client().get_targets
            return p

        except Exception as e:
            LOGGER.error(e)
            raise OpenVasManagerException(e)

