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

import datetime

from typing import Dict


class Client:
    class ReportFormat:
        XML = 'xml'
        PRETTY = 'pretty'

    def get_scans(self) -> Dict:
        raise NotImplementedError()

    @staticmethod
    def _get_epoch_from_lsp(last_pull: datetime.datetime) -> int:
        return int(last_pull.timestamp()) if last_pull else 0

    def download_scan(self, scan_id, report_format):
        raise NotImplementedError()
