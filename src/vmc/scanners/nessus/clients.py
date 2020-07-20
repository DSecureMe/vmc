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


class NessusClient(Client):

    def __init__(self, config: Config):
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

    def get_scans(self, last_modification_date=None) -> Dict:
        if last_modification_date:
            last_modification_date = self._get_epoch_from_lsp(last_modification_date)
            return self._action(action=F"scans?last_modification_date={last_modification_date}", method="GET")
        return self._action(action="scans", method="GET")

    @staticmethod
    def _get_epoch_from_lsp(last_pull: datetime.datetime) -> int:
        return int(last_pull.timestamp()) if last_pull else 0

    def get_scan_detail(self, scan_id: int) -> Dict:
        return self._action(action=F'scans/{scan_id}', method='GET')

    def download_scan(self, scan_id: int):
        extra = {"format": "nessus"}
        res = self._action(F'scans/{scan_id}/export', method="POST", extra=extra)

        if 'file' in res:
            file_id = res["file"]
            while self._export_in_progress(scan_id, file_id):
                time.sleep(2)

            content = self._action(F'scans/{scan_id}/export/{file_id}/download', method="GET", download=True)
            return BytesIO(content)
        return None

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

    def _export_in_progress(self, scan_id, file_id):
        res = self._action(F'scans/{scan_id}/export/{file_id}/status', method="GET")
        return res["status"] != "ready"
