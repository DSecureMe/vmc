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
import uuid
import datetime
import netaddr
from unittest import skipIf
from unittest.mock import patch, MagicMock, call

from django.test import TestCase


from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.scanners.nessus.parsers import NessusReportParser
from vmc.scanners.nessus.apps import NessusConfig
from vmc.scanners.nessus.clients import NessusClient, _NessusClient8, _NessusClient7

from vmc.knowledge_base import metrics
from vmc.config.test_settings import elastic_configured
from vmc.elasticsearch.tests import ESTestCase


from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.common.tests import get_fixture_location


class ResponseMock:

    def __init__(self, resp, status_code):
        self.text = resp
        self.status_code = status_code

    def json(self):
        return self.text


class NessusConfigTest(TestCase):
    fixtures = ['nessus_config.json']

    def test_name(self):
        self.assertEqual(NessusConfig.name, 'vmc.scanners.nessus')

    @patch('vmc.scanners.nessus.clients.requests')
    def test_registry(self, request_mock):
        request_mock.get.return_value = ResponseMock({"nessus_ui_version": '7.2.3'}, 200)
        manager = scanners_registry.get(Config.objects.first())

        self.assertIsInstance(manager.get_parser(), NessusReportParser)
        self.assertIsInstance(manager.get_client(), NessusClient)


class NessusClient7Test(TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        self.config = Config.objects.first()
        self.uut = _NessusClient7(self.config)


    @patch('vmc.scanners.nessus.clients.requests')
    def test_download_scan_xml(self, request_mock):
        rsp = MagicMock(content=b'content', status_code=200)
        rsp.json.return_value = {'file': "file", 'status': 'ready'}
        request_mock.request.side_effect = [rsp, rsp, rsp]

        self.uut.download_scan(1, NessusClient.ReportFormat.XML)

        request_mock.request.assert_has_calls([
            call('POST', 'http://test:80/scans/1/export', data='{"format": "nessus"}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/scans/1/export/file/status', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/scans/1/export/file/download', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False)
        ])

    @patch('vmc.scanners.nessus.clients.requests')
    def test_download_scan_pretty(self, request_mock):
        rsp = MagicMock(content=b'content', status_code=200)
        rsp.json.return_value = {'file': "file", 'status': 'ready'}
        request_mock.request.side_effect = [rsp, rsp, rsp]

        self.uut.download_scan(1, NessusClient.ReportFormat.PRETTY)

        request_mock.request.assert_has_calls([
            call('POST', 'http://test:80/scans/1/export', data='{"format": "html", "chapters": "vuln_by_host"}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY',
                          'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/scans/1/export/file/status', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY',
                          'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/scans/1/export/file/download', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY',
                          'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False)
        ])


class NessusClient8Test(TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        self.config = Config.objects.first()
        self.uut = _NessusClient8(self.config)


    @patch('vmc.scanners.nessus.clients.requests')
    def test_download_scan_xml(self, request_mock):
        rsp = MagicMock(content=b'content', status_code=200)
        rsp.json.return_value = {'file': "file", 'status': 'ready', 'token': 'token'}
        request_mock.request.side_effect = [rsp, rsp, rsp]

        self.uut.download_scan(1, NessusClient.ReportFormat.XML)

        request_mock.request.assert_has_calls([
            call('POST', 'http://test:80/scans/1/export', data='{"format": "nessus"}', headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/tokens/token/status', data='{}', headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/tokens/token/download', data='{}', headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json', 'Accept': 'text/plain'}, verify=False)
        ], any_order=True)

    @patch('vmc.scanners.nessus.clients.requests')
    def test_download_scan_pretty(self, request_mock):
        rsp = MagicMock(content=b'content', status_code=200)
        rsp.json.return_value = {'file': "file", 'status': 'ready', 'token': 'token'}
        request_mock.request.side_effect = [rsp, rsp, rsp]

        self.uut.download_scan(1, NessusClient.ReportFormat.PRETTY)

        request_mock.request.assert_has_calls([
            call('POST', 'http://test:80/scans/1/export',
                 data='{"format": "html", "chapters": "custom;vuln_by_host;remediations;vulnerabilities", "reportContents": {"csvColumns": {}, "vulnerabilitySections": {"synopsis": true, "description": true, "see_also": true, "solution": true, "risk_factor": true, "cvss3_base_score": true, "cvss3_temporal_score": true, "cvss_base_score": true, "cvss_temporal_score": true, "stig_severity": true, "references": true, "exploitable_with": true, "plugin_information": true, "plugin_output": true}, "hostSections": {"scan_information": true, "host_information": true}, "formattingOptions": {"page_breaks": true}}, "extraFilters": {"host_ids": [], "plugin_ids": []}}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/tokens/token/status', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False),
            call('GET', 'http://test:80/tokens/token/download', data='{}',
                 headers={'X-ApiKeys': 'accessKey=API_KEY;secretKey=SECRET_KEY', 'Content-type': 'application/json',
                          'Accept': 'text/plain'}, verify=False)
        ])




class NessusClientTest(TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        self.config = Config.objects.first()

    def set_nessus_client(self, request_mock, version='7.2.3'):
        request_mock.get.return_value = ResponseMock({"nessus_ui_version": version}, 200)
        self.uut = NessusClient(self.config)

    def assert_request(self, request_mock, method, action):
        self.headers = {
            'X-ApiKeys': F'accessKey={self.config.username};secretKey={self.config.password}',
            'Content-type': 'application/json',
            'Accept': 'text/plain'
        }
        request_mock.request.assert_called_with(
            method,
            F'http://test:80/{action}',
            data='{}',
            headers=self.headers,
            verify=not self.config.insecure
        )

    @patch('vmc.scanners.nessus.clients.requests')
    def test_call_get_scan_list(self, request_mock):
        self.set_nessus_client(request_mock)
        request_mock.request.return_value = ResponseMock({'scan': 1}, 200)

        scan_list = self.uut.get_scans()
        self.assert_request(request_mock, 'GET', 'scans')
        self.assertEqual(scan_list, {'scan': 1})

        self.config.last_scans_pull = datetime.datetime.fromtimestamp(1551398400)
        self.uut = NessusClient(self.config)
        scan_list2 = self.uut.get_scans()
        self.assert_request(request_mock, 'GET', 'scans?last_modification_date=1551398400')
        self.assertEqual(scan_list2, {'scan': 1})

    @patch('vmc.scanners.nessus.clients.requests')
    def test_call_get_scan_detail(self, request_mock):
        self.set_nessus_client(request_mock)
        request_mock.request.return_value = ResponseMock({'foo': 1}, 200)

        resp = self.uut.get_scan_detail(1)
        self.assert_request(request_mock, 'GET', 'scans/1')

        self.assertEqual(resp, {'foo': 1})


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class NessusReportParserTest(ESTestCase, TestCase):
    fixtures = ['nessus_config.json']

    def setUp(self):
        super().setUp()
        self.config = Config.objects.first()
        self.internal_xml = open(get_fixture_location(__file__, 'internal.xml'))
        self.internal_targets_xml = open(get_fixture_location(__file__, 'internal_targets.xml'))
        self.uut = NessusReportParser(self.config)
        self.addr1 = "192.168.1.1/32"
        self.addr2 = "192.168.1.1"
        self.addr3 = "10.0.0.1/30"
        self.addr4 = "192.168.2.1-192.168.2.5"

    def test_get_scans_ids(self):
        self.assertEqual(self.uut.get_scans_ids(
            {'scans': [
                {'id': 3, 'folder_id': 3},
                {'id': 2, 'folder_id': 2},
                {'id': 3, 'folder_id': 1}
            ], 'folders': [{'type': 'trash', 'id': 1, 'name': 'Trash'},
                           {'type': 'custom', 'id': 2, 'name':'test'}]}), [2])

    def test_get_scans_ids_with_filter(self):
        self.config.filter = r'test$'
        self.config.save()

        self.uut = NessusReportParser(self.config)
        self.assertEqual(self.uut.get_scans_ids(
            {'scans': [
                {'id': 3, 'folder_id': 3},
                {'id': 2, 'folder_id': 2},
                {'id': 3, 'folder_id': 1}
            ],
                'folders': [{'type': 'trash', 'id': 1, 'name': 'Trash'},
                            {'type': 'custom', 'id': 2, 'name': 'test'},
                            {'type': 'custom', 'id': 3, 'name': 'test2'}]}), [2])

    def test_parse_call(self):
        parsed, scanned_hosts = self.uut.parse(self.internal_xml, "internal.xml")
        vuln_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '10.31.2.30-tcp-22-70658-CVE-2008-5161'))
        self.assertEqual(len(parsed), 2)
        self.assertIsInstance(parsed[vuln_id], VulnerabilityDocument)
        self.assertEqual(str(parsed[vuln_id].scan_date), '2020-07-19 11:49:32')
        self.assertEqual(parsed[vuln_id].asset.ip_address, '10.31.2.30')
        self.assertEqual(parsed[vuln_id].cve.id, 'CVE-2008-5161')
        self.assertEqual(parsed[vuln_id].port, '22')
        self.assertEqual(parsed[vuln_id].svc_name, 'ssh')
        self.assertEqual(parsed[vuln_id].protocol, 'tcp')
        self.assertEqual(parsed[vuln_id].tenant, None)
        self.assertEqual(parsed[vuln_id].name, 'SSH Server CBC Mode Ciphers Enabled')
        self.assertEqual(parsed[vuln_id].solution, 'Contact the vendor or consult product documentation to disable CBC mode '
                                        'cipher encryption, and enable CTR or GCM cipher mode encryption.')
        self.assertEqual(parsed[vuln_id].scan_file_url, "internal.xml")
        self.assertIn('The SSH server is configured to support Cipher Block Chaining (CBC)', parsed[vuln_id].description)

        self.assertEqual(1, len(scanned_hosts))
        self.assertEqual(scanned_hosts[0].ip_address, '10.31.2.30')
        self.assertEqual(str(scanned_hosts[0].last_scan_date), '2020-07-19 11:49:32')


        vuln_id = str(uuid.uuid3(uuid.NAMESPACE_OID, '10.31.2.30-tcp-23-42263-NESSUS-42263'))
        self.assertIsInstance(parsed[vuln_id], VulnerabilityDocument)
        self.assertEqual(parsed[vuln_id].asset.ip_address, '10.31.2.30')
        self.assertEqual(parsed[vuln_id].asset.mac_address, '3E:CE:D5:62:DF:E2')
        self.assertEqual(parsed[vuln_id].cve.id, 'NESSUS-42263')
        self.assertEqual(parsed[vuln_id].cve.base_score_v3, 6.5)

        self.assertEqual(parsed[vuln_id].cve.attack_vector_v3, metrics.AttackVectorV3.NETWORK)
        self.assertEqual(parsed[vuln_id].cve.attack_complexity_v3, metrics.AttackComplexityV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.privileges_required_v3, metrics.PrivilegesRequiredV3.NONE)
        self.assertEqual(parsed[vuln_id].cve.user_interaction_v3, metrics.UserInteractionV3.NONE)
        self.assertEqual(parsed[vuln_id].cve.scope_v3, metrics.ScopeV3.UNCHANGED)
        self.assertEqual(parsed[vuln_id].cve.confidentiality_impact_v3, metrics.ImpactV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.integrity_impact_v3, metrics.ImpactV3.LOW)
        self.assertEqual(parsed[vuln_id].cve.availability_impact_v3, metrics.ImpactV3.NONE)

        self.assertEqual(parsed[vuln_id].cve.base_score_v2, 5.8)
        self.assertEqual(parsed[vuln_id].cve.access_vector_v2, metrics.AccessVectorV2.NETWORK)
        self.assertEqual(parsed[vuln_id].cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM)
        self.assertEqual(parsed[vuln_id].cve.authentication_v2, metrics.AuthenticationV2.NONE)
        self.assertEqual(parsed[vuln_id].cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(parsed[vuln_id].cve.integrity_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(parsed[vuln_id].cve.availability_impact_v2, metrics.ImpactV2.NONE)


    def test__get_targets_call(self):

        multiple_targets = self.uut.get_targets(self.internal_targets_xml)

        self.assertEqual(len(multiple_targets.iter_cidrs()), 9)
        self.assertEqual(netaddr.IPNetwork("10.10.10.0/8"), multiple_targets.iter_cidrs()[0])
        self.assertEqual(netaddr.IPNetwork("192.168.1.1/32"), multiple_targets.iter_cidrs()[1])
        self.assertEqual(netaddr.IPNetwork("192.168.2.10/31"), multiple_targets.iter_cidrs()[2])
        self.assertEqual(netaddr.IPNetwork("192.168.2.12/30"), multiple_targets.iter_cidrs()[3])
        self.assertEqual(netaddr.IPNetwork("192.168.2.16/28"), multiple_targets.iter_cidrs()[4])
        self.assertEqual(netaddr.IPNetwork("192.168.2.32/27"), multiple_targets.iter_cidrs()[5])
        self.assertEqual(netaddr.IPNetwork("192.168.2.64/28"), multiple_targets.iter_cidrs()[6])
        self.assertEqual(netaddr.IPNetwork("192.168.2.80/29"), multiple_targets.iter_cidrs()[7])
        self.assertEqual(netaddr.IPNetwork("192.168.2.88/32"), multiple_targets.iter_cidrs()[8])

        ip_set = netaddr.IPSet()
        for n in range(9, 90, 1):
            ip_set.add(F"192.168.2.{n}")

        check_set = netaddr.IPSet()
        for cidr in multiple_targets.iter_cidrs()[-7:]:
            check_set.add(cidr)

        for ip in ip_set:
            if str(ip) == "192.168.2.9" or str(ip) == "192.168.2.89":
                self.assertFalse(ip in check_set)
            else:
                self.assertTrue(ip in check_set)
