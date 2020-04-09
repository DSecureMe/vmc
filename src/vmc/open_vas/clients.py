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
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError

from vmc.open_vas.models import Config


class OpenVasClientError(GvmError):
    pass


class OpenVasClient:

    def __init__(self, config: Config):
        self._config = config
        self._gmp = None

    def connect(self):
        if not self._gmp:
            conn = TLSConnection(hostname=self._config.host, port=self._config.port)
            self._gmp = Gmp(connection=conn, transform=EtreeTransform())
            self._gmp.connect()

    def get_reports(self):
        # TODO: time filter
        return self._gmp.get_reports()

    def get_report(self, report_id):
        return self._gmp.get_report(report_id)
