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

import re
import json
import logging
import time
import datetime
import requests

from typing import Dict
from io import BytesIO

from vmc.scanners.models import Config
from vmc.scanners.clients import Client

LOGGER = logging.getLogger(__name__)


class NessusClientException(Exception):
    pass


class _NessusClientBase:

    def __init__(self, config: Config):
        self._config = config
        self.url = config.get_url()
        self.insecure = config.insecure
        self.headers = {
            'X-ApiKeys': F'accessKey={config.username};secretKey={config.password}',
            'Content-type': 'application/json',
            'Accept': 'text/plain'
        }

        if self.insecure and hasattr(requests, 'packages'):
            requests.packages.urllib3.disable_warnings()

    def _action(self, action: str, method: str, extra: dict = None, download: bool = False) -> dict:
        payload = dict()
        if extra:
            payload.update(extra)
        payload = json.dumps(payload)
        result = dict()

        url = F'{self.url}/{action}'

        try:

            resp = requests.request(method, url, data=payload, verify=not self.insecure, headers=self.headers)
        except Exception as ex:
            LOGGER.error(F'Could not connect to {url}. Exiting!')
            raise NessusClientException(ex)

        if resp.status_code != 200:
            self._raise_exception(self.headers, url, resp.status_code, payload, resp.content)

        if download:
            result = resp.content
        elif resp.text:
            result = resp.json()
        return result

    def get_scans(self) -> Dict:
        if self._config.last_scans_pull:
            last_modification_date = self._get_epoch_from_lsp(self._config.last_scans_pull)
            return self._action(action=F"scans?last_modification_date={last_modification_date}", method="GET")
        return self._action(action="scans", method="GET")

    @staticmethod
    def _get_epoch_from_lsp(last_pull: datetime.datetime) -> int:
        return int(last_pull.timestamp()) if last_pull else 0

    def get_scan_detail(self, scan_id: int) -> Dict:
        return self._action(action=F'scans/{scan_id}', method='GET')


    @staticmethod
    def _raise_exception(headers, endpoint, status_code, data=None, content=None):
        data = json.loads(data)
        if 'X-ApiKeys' in headers:
            data['X-ApiKeys'] = '*********'

        LOGGER.error("*****************START ERROR*****************")
        LOGGER.error(F"JSON    : {data}")
        LOGGER.error(F"HEADERS : {headers}")
        LOGGER.error(F"URL     : {endpoint}")
        LOGGER.error("******************END ERROR******************")
        LOGGER.error(F"RESPONSE CODE: {status_code}")
        raise NessusClientException(
            F'request data: {data}\n'
            F'request headers: {headers}\n'
            F'url: {endpoint}\n'
            F'response code: {status_code}\n'
            F'response body: {content}\n')


class _NessusClient7(_NessusClientBase):
    version = r'^7.'

    def __init__(self, config: Config):
        super().__init__(config)

    def download_scan(self, scan_id: int, report_format: Client.ReportFormat.XML):
        extra = self._get_report_format(report_format)
        res = self._action(F'scans/{scan_id}/export', method="POST", extra=extra)

        if 'file' in res:
            file_id = res["file"]
            while self._export_in_progress(scan_id, file_id):
                time.sleep(2)

            content = self._action(F'scans/{scan_id}/export/{file_id}/download', method="GET", download=True)
            return BytesIO(content)
        return None

    def _export_in_progress(self, scan_id, file_id):
        res = self._action(F'scans/{scan_id}/export/{file_id}/status', method="GET")
        return res["status"] != "ready"

    @staticmethod
    def _get_report_format(report_format):
        if report_format == NessusClient.ReportFormat.PRETTY:
            return {"format": "html", "chapters": "vuln_by_host"}
        return {"format": "nessus"}

class _NessusClient8(_NessusClientBase):
    version = r'^8.'

    def download_scan(self, scan_id: int, report_format: Client.ReportFormat.XML):
        extra = self._get_report_format(report_format)
        res = self._action(F'scans/{scan_id}/export', method="POST", extra=extra)

        if 'file' in res:
            token = res["token"]
            while self._export_in_progress(token):
                time.sleep(2)

            content = self._action(F'tokens/{token}/download', method="GET", download=True)
            return BytesIO(content)
        return None

    def _export_in_progress(self, token):
        res = self._action(F'tokens/{token}/status', method="GET")
        return res["status"] != "ready"

    @staticmethod
    def _get_report_format(report_format):
        if report_format == NessusClient.ReportFormat.PRETTY:
            return {"format": "html",
                    "chapters": "custom;vuln_by_host;remediations;vulnerabilities",
                    "reportContents": {
                        "csvColumns": {},
                        "vulnerabilitySections": {
                            "synopsis": True,
                            "description": True,
                            "see_also": True,
                            "solution": True,
                            "risk_factor": True,
                            "cvss3_base_score": True,
                            "cvss3_temporal_score": True,
                            "cvss_base_score": True,
                            "cvss_temporal_score": True,
                            "stig_severity": True,
                            "references": True,
                            "exploitable_with": True,
                            "plugin_information": True,
                            "plugin_output": True
                        },
                        "hostSections": {
                            "scan_information": True,
                            "host_information": True
                        },
                        "formattingOptions": {
                            "page_breaks": True
                        }
                    },
             "extraFilters": {
                 "host_ids": [],
                 "plugin_ids": []
             }
            }
        return {"format": "nessus"}

class NessusClient(Client):
    class ReportFormat:
        XML = 'xml'
        PRETTY = 'html'

    def __init__(self, config: Config):
        self._url = config.get_url()
        self._config = config

        if config.insecure and hasattr(requests, 'packages'):
            requests.packages.urllib3.disable_warnings()

        try:
            self._version = self._get_version()

            if re.match(_NessusClient8.version, self._version):
                LOGGER.debug('Using nessus client version 8')
                self.client = _NessusClient8(config)
            elif re.match(_NessusClient7.version, self._version):
                LOGGER.debug('Using nessus client version 7')
                self.client = _NessusClient7(config)
            else:
                raise Exception(F'Unknown nessus version {self._version}')

        except Exception as ex:
            LOGGER.error(F'{ex}. Exiting!')
            raise NessusClientException(ex)

    def get_version(self) -> str:
        if not self._version:
            self._version = self._get_version()
        return self._version

    def _get_version(self) -> str:
        try:
            resp = requests.get(F'{self._url}/server/properties', verify=not self._config.insecure)
            version = resp.json()
            return version['nessus_ui_version']

        except Exception as ex:
            LOGGER.error(F'{ex}. Exiting!')
            raise NessusClientException(ex)


    def get_scans(self) -> Dict:
        return self.client.get_scans()

    def get_scan_detail(self, scan_id: int) -> Dict:
        return self.client.get_scan_detail(scan_id)

    def download_scan(self, scan_id: int, report_format: Client.ReportFormat.XML):
        return self.client.download_scan(scan_id, report_format)
