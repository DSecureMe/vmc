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
import logging
import json
from vmc.ralph.models import Config
import requests


LOGGER = logging.getLogger(__name__)


class SSLException(Exception):
    pass


class AssetIdException(Exception):
    pass


class NoAssetsInDb(Exception):
    pass


class Ralph:

    def __init__(self, config: Config):

        self.url = config.url
        self.username = config.username
        self.password = config.password
        self.api_token = None

    def get_token(self):

        headers = {
            'Content-Type': 'application/json'
        }
        endpoint = self.url+'/api-token-auth/'
        data = {
            'username': self.username,
            'password': self.password
        }

        try:
            r = requests.request('POST', endpoint, headers=headers, data=json.dumps(data))

            if r.status_code != 200:
                LOGGER.error("*****************START ERROR*****************")
                LOGGER.error("JSON    : %s", data)
                LOGGER.error("HEADERS : %s", headers)
                LOGGER.error("URL     : %s", endpoint)
                LOGGER.error("******************END ERROR******************")
                LOGGER.debug("RESPONSE CODE: %d", r.status_code)

        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('{} for {}.'.format(ssl_error, endpoint))
        except requests.exceptions.ConnectionError:
            raise Exception("Could not connect to {}. Exiting!".format(endpoint))

        result = r.json()
        return result['token']

    def get_host_data_by_id(self, host_id):

        headers = {
            'Authorization': 'Token '+self.get_token()
        }
        endpoint = self.url+'/api/data-center-assets/'+str(host_id)+'/?format=json'

        try:
            r = requests.request('GET', endpoint, headers=headers)
            if r.status_code != 200:
                LOGGER.error("*****************START ERROR*****************")
                LOGGER.error("HEADERS : %s", headers)
                LOGGER.error("URL     : %s", endpoint)
                LOGGER.error("******************END ERROR******************")
                LOGGER.debug("RESPONSE CODE: %d", r.status_code)

        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('{} for {}.'.format(ssl_error, endpoint))
        except requests.exceptions.ConnectionError:
            raise Exception("Could not connect to {}. Exiting!".format(endpoint))

        result = r.text
        if 'detail' in json.dumps(result):
            return 'Such asset doesn\'t exist'
        return result

    def get_all_assets(self) -> list:
        new_assets = []

        headers = {
            'Authorization': 'Token ' + self.get_token()
        }
        limit = 500
        endpoint = self.url + '/api/data-center-assets/?format=json&limit='+str(limit)
        try:
            r = requests.request('GET', endpoint, headers=headers)
            if r.status_code != 200:
                LOGGER.error("*****************START ERROR*****************")
                LOGGER.error("HEADERS : %s", headers)
                LOGGER.error("URL     : %s", endpoint)
                LOGGER.error("******************END ERROR******************")
                LOGGER.debug("RESPONSE CODE: %d", r.status_code)

        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('{} for {}.'.format(ssl_error, endpoint))
        except requests.exceptions.ConnectionError:
            raise Exception("Could not connect to {}. Exiting!".format(endpoint))

        j_response = json.loads(r.text)

        if int(j_response['count']) > 0:
            while True:
                asset_list = j_response['results']
                new_assets.extend(asset_list)

                LOGGER.debug('Next API page: %s', j_response['next'])
                if j_response['next'] is None:
                    break
                else:
                    r = requests.post(j_response['next'], headers=headers)
                    j_response = json.loads(r.text)

        else:
            raise NoAssetsInDb('Count from API call was: {}'.format(j_response['count']))
        return new_assets
