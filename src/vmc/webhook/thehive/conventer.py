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

from vmc.webhook.thehive.models import Case


LOGGER = logging.getLogger(__name__)


class TaskProcessor:

    def __init__(self, hive_client):
        self._hive_client = hive_client

    def process(self, task):
        alert = self._hive_client.get_alert(task.alert_id)
        for art in alert['artifacts']:
            if 'url' in art['dataType']:
                task.scan_url = art['data'].replace(' ', '')
            if 'business-unit' in art['dataType']:
                task.tenant = art['data']
            if 'ip' in art['dataType']:
                task.ip = art['data']
            if 'document-id' in art['dataType']:
                task.document_id = art['data']

        task.title, task.group = self.get_task_title_and_group(alert['title'])
        task.source = alert['source']
        task.description = alert['description']
        task.save()

    @staticmethod
    def get_task_title_and_group(title):
        new_title = ''.join(title.split(':')[1:])
        groups = ['critical', 'medium', 'high']

        for g in groups:
            if g in title:
                return new_title, g

        return new_title, 'low'


class CaseManager:

    def __init__(self, hive_client):
        self._hive = hive_client
        self._updated = set()

    def get_or_create_case(self, scan_url, source, tenant):
        case = Case.objects.filter(scan_url=scan_url).first()
        if not case:

            if tenant:
                title = F'New scan from {source} for {tenant}'
            else:
                title = F'New scan from {source}'

            case_id = self._hive.create_case(title, title)
            case = Case.objects.create(id=case_id, scan_url=scan_url, tenant=tenant)

            return case
        return case

    def merge_alert_to_case(self, case, task):
        try:
            LOGGER.debug(F'Merging case {case.id} to task {task.alert_id}')
            self._hive.merge_alert_to_case(task.alert_id, case.id)
            task.case = case
            task.task_id = self._hive.create_task(case.id, task.title, task.description, task.group)
            task.save()
            self._updated.add(case.id)
        except Exception as ex:
            LOGGER.error(ex)

    def update_cases_desc(self):
        for case_id in self._updated:
            obj = Case.objects.get(id=case_id)
            tags = {obj.tenant}
            tags.update({t.ip for t in obj.task_set.all()})

            self._hive.update_case(case_id,
                description=self._build_description(obj),
                tags=tags
            )
        self._updated = {}

    @staticmethod
    def _build_description(obj):
        groups = {}
        for task in obj.task_set.all():
            if task.group not in groups:
                groups.update({task.group: 1})
            else:
                groups[task.group] += 1

        s = F"""**Summary**:\n
Critical: {groups['critical'] if 'critical' in groups else 0}\n
High: {groups['high'] if 'high' in groups else 0}\n
Medium: {groups['medium'] if 'medium' in groups else 0}\n
Low: {groups['low'] if 'low' in groups else 0}\n\n

**Severity Level: Critical**\n
Vulnerabilities that score in the critical range usually have most of the following characteristics:\n
Exploitation of the vulnerability likely results in root-level compromise of servers or infrastructure devices.
Exploitation is usually straightforward, in the sense that the attacker does not need any special authentication credentials or knowledge about individual victims, and does not need to persuade a target user, for example via social engineering, into performing any special functions.
For critical vulnerabilities, is advised that you patch or upgrade as soon as possible, unless you have other mitigating measures in place. For example, a mitigating factor could be if your installation is not accessible from the Internet.\n\n

**Severity Level: High**\n
Vulnerabilities that score in the high range usually have some of the following characteristics:\n
The vulnerability is difficult to exploit.
Exploitation could result in elevated privileges.
Exploitation could result in a significant data loss or downtime.\n\n 

**Severity Level: Medium**\n
Vulnerabilities that score in the medium range usually have some of the following characteristics:\n
Vulnerabilities that require the attacker to manipulate individual victims via social engineering tactics.
Denial of service vulnerabilities that are difficult to set up.
Exploits that require an attacker to reside on the same local network as the victim.
Vulnerabilities where exploitation provides only very limited access.
Vulnerabilities that require user privileges for successful exploitation.\n 
**Severity Level: Low**\n\n
Vulnerabilities in the low range typically have very little impact on an organization's business. Exploitation of such vulnerabilities usually requires local or physical system access.\n\n
**Scan report:** {obj.scan_url}
"""
        return s
