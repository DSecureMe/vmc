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
import requests

from typing import Dict, List

from vmc.ralph.models import Config


LOGGER = logging.getLogger(__name__)


class RalphClientException(Exception):
    pass


class RalphClient:

    def __init__(self, config: Config):
        self._config = config
        self._api_token = None

    def get_data_center_assets(self) -> list:
        return self._get_list('/api/data-center-assets/?format=json&limit=500')

    def get_virtual_assets(self) -> list:
        return self._get_list('/api/virtual-servers/?format=json&limit=500')

    def get_users(self) -> list:
        return self._get_list('/api/users/?format=json&limit=500')

    def get_auth_header(self):
        if not self._api_token:
            self._api_token = self.get_token()
        return {'Authorization': 'Token ' + self._api_token}

    def get_token(self):
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'username': self._config.username,
            'password': self._config.password
        }
        result = self._action('POST', '/api-token-auth/', headers=headers, data=json.dumps(data))
        return result['token']

    def _get_list(self, url: str) -> List:
        results = []
        response = self._action('GET', url, headers=self.get_auth_header())
        if int(response['count']) > 0:
            while True:
                results.extend(response['results'])
                LOGGER.debug('Next API page: %s', response['next'])
                if response['next']:
                    response = self._action('GET', response['next'], headers=self.get_auth_header())
                else:
                    break

        else:
            LOGGER.info(F'Empty response from Ralph {self._config.name}')
        return results

    def _action(self, method: str, url: str, **kwargs) -> Dict:
        if 'http' not in url:
            url = F'{self._config.get_url()}{url}'

        try:
            resp = requests.request(method, url, verify=not self._config.insecure, timeout=360, **kwargs)
        except Exception as ex:
            LOGGER.error(F'Unknown connection exception {ex}')
            raise RalphClientException(ex)

        if resp.status_code != 200:
            self._raise_exception(
                kwargs['headers'], url, resp.status_code,
                kwargs['data'] if 'data' in kwargs else 'None', resp.content
            )

        return resp.json()

    SENSITIVE_KEYS = ('password', 'token', 'authorization', 'api_key', 'apikey', 'secret')
    REDACTED = '*********'

    @classmethod
    def _redact(cls, mapping):
        if not isinstance(mapping, dict):
            return mapping
        return {
            k: cls.REDACTED if k.lower() in cls.SENSITIVE_KEYS else v
            for k, v in mapping.items()
        }

    @classmethod
    def _raise_exception(cls, headers, endpoint, status_code, data=None, content=None):
        safe_data = cls._redact(json.loads(data))
        safe_headers = cls._redact(headers)

        LOGGER.error(
            "Ralph request failed: url=%s response_code=%s",
            endpoint, status_code,
        )
        raise RalphClientException(
            F'request data: {safe_data}\n'
            F'request headers: {safe_headers}\n'
            F'url: {endpoint}\n'
            F'response code: {status_code}\n'
            F'response body: {content}\n')
