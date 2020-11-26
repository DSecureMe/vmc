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
import defusedxml.ElementTree as ET
from io import BytesIO
from base64 import b64decode

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
    _PDF_FORMAT = 'c402cc3e-b531-11e1-9163-406186ea4fc5'
    _XML_FORMAT = 'a994b278-1f62-11e1-96ac-406186ea4fc5'

    class ReportFormat:
        XML = 'xml'
        PRETTY = 'pdf'

    def __init__(self, config: Config):
        self._config = config

    @contextmanager
    def _connect(self):
        conn = TLSConnection(hostname=self._config.host, port=self._config.port)
        with Gmp(connection=conn, transform=EtreeTransform()) as gmp:
            gmp.authenticate(self._config.username, self._config.password)
            yield gmp

    def get_version(self):
        with self._connect() as gmp:
            return gmp.get_version()

    def get_scans(self):
        with self._connect() as gmp:

            f = []
            if self._config.last_scans_pull:
                f.append('created>{}'.format( self._config.last_scans_pull.strftime('%Y-%m-%dT%Hh%M')))

            if self._config.filter:
                f.append(F'tag={self._config.filter}')

            if f:
                return gmp.get_reports(filter='&'.join(f))

            return gmp.get_reports()

    def download_scan(self, scan_id, report_format=Client.ReportFormat.XML):
        with self._connect() as gmp:
            if report_format == OpenVasClient.ReportFormat.PRETTY:
                response = gmp.get_report(scan_id, report_format_id=OpenVasClient._PDF_FORMAT,
                                          details=True, ignore_pagination=True)

                return BytesIO(b64decode("".join(response.itertext())))
            response = gmp.get_report(scan_id, report_format_id=OpenVasClient._XML_FORMAT,
                                      details=True, ignore_pagination=True)
            return BytesIO(ET.tostring(response))

    def _get_target_definition(self, target_id):
        with self._connect() as gmp:
            return gmp.get_target(target_id)

    def get_targets(self, file):
        file = ET.fromstring(file.read())
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

