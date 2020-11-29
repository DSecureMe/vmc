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
from unittest import skipIf
from django.urls import reverse
from django.test import TestCase
from unittest.mock import MagicMock, patch
from parameterized import parameterized
from rest_framework.test import APIClient

from vmc.assets.tests import create_asset
from vmc.knowledge_base.tests import create_cve
from vmc.config.test_settings import elastic_configured
from vmc.elasticsearch.tests import ESTestCase
from vmc.webhook.thehive.models import Task, Case
from vmc.webhook.thehive.client import TheHiveClient
from vmc.webhook.thehive.conventer import TaskProcessor
from vmc.webhook.thehive.conventer import CaseManager
from vmc.webhook.models import TheHive4
from vmc.webhook.thehive.handlers import _process_tasks
from vmc.vulnerabilities.tests import create_vulnerability
from vmc.webhook.thehive.tasks import process_task_log
from vmc.vulnerabilities.documents import VulnerabilityDocument


class TheHiveClientTest(TestCase):

    def setUp(self) -> None:
        self.uut = TheHiveClient('http://localhost', 'token')

    @patch('vmc.webhook.thehive.client.requests')
    def test_call_get_alert(self, requests):
        self.uut.get_alert(1)
        requests.get.assert_called_once_with('http://localhost/api/alert/1', headers={"Authorization": "Bearer token"})

    @patch('vmc.webhook.thehive.client.requests')
    def test_call_create_case(self, requests):
        response = MagicMock()
        response.json.return_value = {'caseId': 12}
        requests.post.return_value = response
        self.assertEqual(12, self.uut.create_case('sample title', 'sample desc'))
        requests.post.assert_called_once_with('http://localhost/api/case', headers={"Authorization": "Bearer token"}, data={
            'title': 'sample title',
            'description': 'sample desc'
        })

    @patch('vmc.webhook.thehive.client.requests')
    def test_call_update_case(self, requests):
        self.uut.update_case(15, 'sample desc', ['tags'])
        requests.patch.assert_called_once_with('http://localhost/api/case/15', headers={"Authorization": "Bearer token"}, json={
            'description': 'sample desc',
            'tags': ['tags']
        })

    @patch('vmc.webhook.thehive.client.requests')
    def test_call_merge_alert_to_case(self, requests):
        self.uut.merge_alert_to_case(15, 12)
        requests.post.assert_called_once_with('http://localhost/api/alert/merge/_bulk', headers={"Authorization": "Bearer token"}, json={
            "caseId": '12',
            "alertIds": ['15']
        })

    @patch('vmc.webhook.thehive.client.requests')
    def test_call_create_task(self, requests):
        self.uut.create_task(15, 'sample title', 'sample desc', 'group')
        requests.post.assert_called_once_with('http://localhost/api/case/15/task', headers={"Authorization": "Bearer token"}, data={
            'title': 'sample title',
            'description': 'sample desc',
            'group': 'group'
        })


class TaskProcessorTests(TestCase):
    ALERT_TITLE = 'New critical vuln:AAA'

    def setUp(self) -> None:
        super(TaskProcessorTests, self).setUp()
        self.client_mock = MagicMock()
        self.uut = TaskProcessor(self.client_mock)

    @parameterized.expand([
        ('New critical vuln:AAA', 'AAA', 'critical'),
        ('New medium vuln:BBB CCC', 'BBB CCC', 'medium'),
        ('New high vuln:DDD CCC', 'DDD CCC', 'high'),
        ('New low vuln:GGG CCC', 'GGG CCC', 'low')
    ])
    def test_get_task_title_and_group(self, given_title, expected_title, expected_group):
        title, group = self.uut.get_task_title_and_group(given_title)
        self.assertEqual(expected_title, title)
        self.assertEqual(expected_group, group)

    def test_update_task_data(self):
        task = Task.objects.create(alert_id=1)

        self.client_mock.get_alert.return_value = {
            'artifacts': [
                {'dataType': 'url', 'data': 'http://url'},
                {'dataType': 'business-unit', 'data': 'tenant'},
                {'dataType': 'ip', 'data': '10.10.10.10'},
                {'dataType': 'document-id', 'data':'ddassdada'}
            ],
            'title': self.ALERT_TITLE,
            'source': 'Nessus',
            'description': 'desc'
        }

        self.uut.process(task)
        self.client_mock.get_alert.assert_called_once_with(1)

        result = Task.objects.filter(alert_id=1).first()
        self.assertEqual(result.title, 'AAA')
        self.assertEqual(result.group, 'critical')
        self.assertEqual(result.source, 'Nessus')
        self.assertEqual(result.document_id, 'ddassdada')
        self.assertEqual(result.description, 'desc')
        self.assertEqual(result.ip, '10.10.10.10')
        self.assertEqual(result.tenant, 'tenant')
        self.assertEqual(result.scan_url, 'http://url')



class CasesManagerTest(TestCase):
    ALERT_TITLE = 'New low vuln:AAA'

    def setUp(self) -> None:
        super(CasesManagerTest, self).setUp()
        self.client_mock = MagicMock()
        self.uut = CaseManager(self.client_mock)

    def prepare_task(self, alert_id=1):
        task = Task.objects.create(alert_id=alert_id)

        self.client_mock.get_alert.return_value = {
            'artifacts': [
                {'dataType': 'url', 'data': 'http://url'},
                {'dataType': 'business-unit', 'data': 'tenant'},
                {'dataType': 'ip', 'data': '10.10.10.10'}
            ],
            'title': self.ALERT_TITLE,
            'source': 'Nessus',
            'description': 'desc'
        }

        p = TaskProcessor(self.client_mock)
        p.process(task)

        return Task.objects.get(alert_id=alert_id)

    def test_call_get_or_create_case_create(self):
        self.client_mock.create_case.return_value = 15

        case = self.uut.get_or_create_case('SCAN_URL', 'SOURCE', 'TENANT')

        self.client_mock.create_case.assert_called_once_with(
            F'New scan from SOURCE for TENANT',
            F'New scan from SOURCE for TENANT'
        )
        self.assertTrue(Case.objects.get(id=15))
        self.assertEqual(case.scan_url, 'SCAN_URL')
        self.assertEqual(case.tenant, 'TENANT')

    def test_call_get_or_create_case_create_without_tenant(self):
        self.client_mock.create_case.return_value = 15

        case = self.uut.get_or_create_case('SCAN_URL', 'SOURCE', None)

        self.client_mock.create_case.assert_called_once_with(
            F'New scan from SOURCE',
            F'New scan from SOURCE'
        )
        self.assertTrue(Case.objects.get(id=15))
        self.assertEqual(case.scan_url, 'SCAN_URL')
        self.assertIsNone(case.tenant)

    def test_call_get_or_create_case_exists(self):
        Case.objects.create(id=9, scan_url='SCAN_URL', tenant='TENANT')
        case = self.uut.get_or_create_case('SCAN_URL', 'SOURCE', 'TENANT')

        self.client_mock.create_case.assert_not_called()
        self.assertEqual(case.scan_url, 'SCAN_URL')
        self.assertEqual(case.tenant, 'TENANT')

    def test_call_merge_alert_to_case(self):
        task = self.prepare_task()
        self.client_mock.create_task.return_value = 2

        case = Case.objects.create(id=9, scan_url='SCAN_URL', tenant='TENANT')

        self.uut.merge_alert_to_case(case, task)

        self.client_mock.merge_alert_to_case.assert_called_once_with(task.alert_id, case.id)
        self.client_mock.create_task.assert_called_once_with(case.id, task.title, task.description, task.group)

        t_result = Task.objects.get(alert_id=1)
        self.assertEqual(t_result.case_id, case.id)
        self.assertEqual(t_result.task_id, '2')
        self.assertEqual(self.uut._updated, {9})

    def test_call_update_cases_desc(self):
        self.client_mock.create_task.return_value = 11
        task_1 = self.prepare_task()
        task_2 = self.prepare_task(alert_id=2)
        task_3 = self.prepare_task(alert_id=3)
        case = Case.objects.create(id=9, scan_url='SCAN_URL', tenant='TENANT')

        self.uut.merge_alert_to_case(case, task_1)
        self.uut.merge_alert_to_case(case, task_2)
        self.uut.merge_alert_to_case(case, task_3)

        self.uut.update_cases_desc()

        self.client_mock.update_case.assert_called_once_with(
            case.id,
            description="**Summary**:\n\nCritical: 0\n\nHigh: 0\n\nMedium: 0\n\nLow: 3\n\n\n\n**Severity Level: Critical**\n\nVulnerabilities that score in the critical range usually have most of the following characteristics:\n\nExploitation of the vulnerability likely results in root-level compromise of servers or infrastructure devices.\nExploitation is usually straightforward, in the sense that the attacker does not need any special authentication credentials or knowledge about individual victims, and does not need to persuade a target user, for example via social engineering, into performing any special functions.\nFor critical vulnerabilities, is advised that you patch or upgrade as soon as possible, unless you have other mitigating measures in place. For example, a mitigating factor could be if your installation is not accessible from the Internet.\n\n\n\n**Severity Level: High**\n\nVulnerabilities that score in the high range usually have some of the following characteristics:\n\nThe vulnerability is difficult to exploit.\nExploitation could result in elevated privileges.\nExploitation could result in a significant data loss or downtime.\n\n \n\n**Severity Level: Medium**\n\nVulnerabilities that score in the medium range usually have some of the following characteristics:\n\nVulnerabilities that require the attacker to manipulate individual victims via social engineering tactics.\nDenial of service vulnerabilities that are difficult to set up.\nExploits that require an attacker to reside on the same local network as the victim.\nVulnerabilities where exploitation provides only very limited access.\nVulnerabilities that require user privileges for successful exploitation.\n \n**Severity Level: Low**\n\n\nVulnerabilities in the low range typically have very little impact on an organization's business. Exploitation of such vulnerabilities usually requires local or physical system access.\n\n\n**Scan report:** SCAN_URL\n",
            tags={'TENANT', '10.10.10.10'})


class AlertCreateTest(TestCase):
    fixtures = ['config.json']
    URL = reverse('webhook:thehive')

    def setUp(self):
        self.config = TheHive4.objects.first()
        self.client = APIClient()

    def test_call_get(self):
        resp = self.client.get(F'{self.URL}')
        self.assertEqual(resp.status_code, 405)


    def test_empty_post(self):
        resp = self.client.post(F'{self.URL}')
        self.assertEqual(resp.status_code, 200)

    def test_invalid_type(self):
        resp = self.client.post(F'{self.URL}', {
            'objectType': 'alert',
            'operation': 'create',
            'details': {'type': 'aaa'}
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Task.objects.count(), 0)

    def test_create_task(self):
        resp = self.client.post(F'{self.URL}', {
            'objectType': 'alert',
            'operation': 'create',
            'details': {
                '_id': '1',
                'type': 'vmc\\vulnerability',
            }
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Task.objects.count(), 1)

    @patch('vmc.webhook.thehive.handlers.TheHiveClient')
    @patch('vmc.webhook.thehive.handlers.TaskProcessor')
    @patch('vmc.webhook.thehive.handlers.CaseManager')
    def test__process_tasks(self, case_manager, task_processor, client):
        task = Task.objects.create(alert_id=2, tenant='TENANT', title='TITLE', scan_url='URL', source="SOURCE")
        case_manager().get_or_create_case.return_value = 'case'
        _process_tasks(task)

        client.assert_called_once_with(self.config.get_url(), self.config.token)
        task_processor.assert_called_once_with(client())
        case_manager.assert_called_with(client())
        case_manager().get_or_create_case.assert_called_once_with(task.scan_url, task.source, task.tenant)
        case_manager().merge_alert_to_case.assert_called_once_with('case', task)
        case_manager().update_cases_desc.assert_called_once()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class LogCreateTaskTest(ESTestCase, TestCase):
    fixtures = ['config.json']

    def test_call(self):
        vuln = create_vulnerability(create_asset(), create_cve())
        task = Task.objects.create(task_id=15, document_id=vuln.meta.id)
        process_task_log({
            'operation': 'create',
            'objectType': 'case_task_log',
            'object': {
                'message': 'fixed',
                'case_task': {'id': task.task_id}}}
        )
        process_task_log({
            'operation': 'create',
            'objectType': 'case_task_log',
            'object': {
                'message': 'fixed',
                'case_task': {'id': task.task_id}}}
        )
        vulns = VulnerabilityDocument.search().filter('match', id=vuln.id).execute()
        self.assertEqual(len(vulns.hits), 1)
        self.assertEqual(vulns.hits[0].tags, ['test', 'FIXED'])
