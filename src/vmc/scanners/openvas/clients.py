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
from contextlib import contextmanager

import logging
import netaddr

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

from vmc.scanners.clients import Client
from vmc.scanners.models import Config
from vmc.common.utils import handle_ranges


LOGGER = logging.getLogger(__name__)


class OpenVasClient(Client):

    def __init__(self, config: Config):
        self._config = config

    @contextmanager
    def _connect(self):
        conn = TLSConnection(hostname=self._config.host, port=self._config.port)
        with Gmp(connection=conn, transform=EtreeTransform()) as gmp:
            gmp.authenticate(self._config.username, self._config.password)
            yield gmp

    def get_scans(self, last_modification_date=None):
        with self._connect() as gmp:
            if last_modification_date:
                date = last_modification_date.strftime('%Y-%m-%dT%Hh%M')
                return gmp.get_reports(filter=F'created>{date}')
            return gmp.get_reports()

    def download_scan(self, scan_id):
        with self._connect() as gmp:
            return gmp.get_report(scan_id)

    def _get_target_definition(self, target_id):
        with self._connect() as gmp:
            return gmp.get_target(target_id)

    def get_targets(self, file):
        target_id = file.find(".//report/task/target").attrib["id"]
        target = self._get_target_definition(target_id)
        hosts = target.find(".//target/hosts").text
        targets = netaddr.IPSet()
        for h in hosts.split(sep=","):
            h = h.strip()
            if "/" in h:
                targets.add(netaddr.IPNetwork(h))
            elif "-" in h:
                r = h.split(sep="-")
                ip_range = handle_ranges(r)
                try:
                    targets.add(netaddr.IPRange(start=ip_range[0], end=ip_range[1]))
                except netaddr.core.AddrFormatError:
                    LOGGER.error(F"Couldn't parse range: {h}. Skipping that one!")
            else:
                try:
                    targets.add(netaddr.IPAddress(h))
                except netaddr.core.AddrFormatError:
                    LOGGER.error(F"Couldn't parse target: {h}. Skipping that one!")

        return targets

