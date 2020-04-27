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


class SSLException(Exception):
    pass


class RalphClient:

    def __init__(self, config: Config):
        self._config = config
        self._api_token = None

    def get_assets(self) -> list:
        return self._get_list('/api/data-center-assets/?format=json&limit=500')

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
        try:

            if 'http' not in url:
                url = F'{self._config.get_url()}{url}'

            resp = requests.request(method, url, verify=not self._config.insecure, **kwargs)

            if resp.status_code != 200:
                self._print_debug(kwargs['headers'], url, resp.status_code,
                                  kwargs['data'] if 'data' in kwargs else 'None')
                return dict()

        except requests.exceptions.SSLError as ssl_error:
            raise SSLException(F'{ssl_error} for {url}.')
        except requests.exceptions.ConnectionError:
            raise Exception(F"Could not connect to {url}. Exiting!")

        return resp.json()

    @staticmethod
    def _print_debug(headers, endpoint, status_code, data=None):
        LOGGER.debug("*****************START ERROR*****************")
        LOGGER.debug(F"JSON    : {data}")
        LOGGER.debug(F"HEADERS : {headers}")
        LOGGER.debug(F"URL     : {endpoint}")
        LOGGER.debug("******************END ERROR******************")
        LOGGER.debug(F"RESPONSE CODE: {status_code}")
