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
import requests


LOGGER = logging.getLogger(__name__)


class TheHiveClient:
    def __init__(self, url, token):
        self._url = url
        self.headers = {"Authorization": F"Bearer {token}"}

    def get_alert(self, alert_id):
        return TheHiveClient._log_response_if_error(
            requests.get(F"{self._url}/api/alert/{alert_id}", headers=self.headers))

    def create_case(self, title, description):
        return TheHiveClient._log_response_if_error(requests.post(F"{self._url}/api/case", headers=self.headers, data={
            'title': title,
            'description': description
        }))['caseId']

    def update_case(self, case_id, description, tags):
        return TheHiveClient._log_response_if_error(
            requests.patch(F"{self._url}/api/case/{case_id}", headers=self.headers, json={
                'description': description,
                'tags': list(tags)
        }))

    def merge_alert_to_case(self, alert_id, case_id):
        return TheHiveClient._log_response_if_error(
            requests.post(F"{self._url}/api/alert/merge/_bulk", headers=self.headers, json={
                "caseId": str(case_id),
                "alertIds": [str(alert_id)]
        }))

    def create_task(self, case_id, title, description, group):
        return TheHiveClient._log_response_if_error(
            requests.post(F"{self._url}/api/case/{case_id}/task", headers=self.headers, data={
                'title': title,
                'description': description,
                'group': group
        }))['id']

    @staticmethod
    def _log_response_if_error(resp):
        result = resp.json()
        if resp.status_code != requests.codes.OK and resp.status_code != requests.codes.CREATED:
            LOGGER.error(F'Response code {resp.status_code}, body {result}')
        return result
