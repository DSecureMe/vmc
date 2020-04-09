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
from typing import Dict
from io import BytesIO

import requests

from vmc.nessus.models import Config

LOGGER = logging.getLogger(__name__)


class SSLException(Exception):
    pass


class NessusClient:

    def __init__(self, config: Config):
        self.url = config.get_url()
        self.api_key = config.api_key
        self.secret_key = config.secret_key
        self.insecure = config.insecure
        self.headers = {
            'X-ApiKeys': 'accessKey={};secretKey={}'.format(self.api_key, self.secret_key),
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

            if resp.status_code != 200:
                LOGGER.error("*****************START ERROR*****************")
                LOGGER.error(F"JSON    : {payload}")
                LOGGER.error(F"HEADERS : {self.headers}")
                LOGGER.error(F"URL     : {url}")
                LOGGER.error(F"METHOD  : {method}")
                LOGGER.error("******************END ERROR******************")
                LOGGER.debug(F"RESPONSE CODE: {resp.status_code}")

        except requests.exceptions.SSLError as ssl_error:
            raise SSLException(F'{ssl_error} for {url}.')
        except requests.exceptions.ConnectionError:
            raise Exception(F'Could not connect to {url}. Exiting!')

        if download:
            result = resp.content
        elif resp.text:
            result = resp.json()
        return result

    def get_scan_list(self, last_modification_date=0) -> Dict:
        if last_modification_date == 0:
            return self._action(action="scans", method="GET")
        return self._action(action=F"scans?last_modification_date={last_modification_date}", method="GET")

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

    def _export_in_progress(self, scan_id, file_id):
        res = self._action(F'scans/{scan_id}/export/{file_id}/status', method="GET")
        return res["status"] != "ready"
