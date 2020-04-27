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

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

from vmc.scanners.clients import Client
from vmc.scanners.models import Config


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
