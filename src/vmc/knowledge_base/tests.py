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

from decimal import Decimal
from unittest import skipIf
from unittest.mock import patch

from django.test import TestCase
from parameterized import parameterized

from vmc.common.utils import thread_pool_executor
from vmc.common.tests import get_fixture_location
from vmc.elasticsearch import Search
from vmc.elasticsearch.tests import ESTestCase
from vmc.config.test_settings import elastic_configured
from vmc.knowledge_base.documents import CveDocument, CweDocument

from vmc.knowledge_base.factories import CveFactory, CWEFactory
from vmc.knowledge_base import metrics
from vmc.knowledge_base.utils import calculate_base_score_v2, calculate_base_score_v3
from vmc.knowledge_base.tasks import update_exploits, update_cwe, update_cve


def create_cve(cve_id='CVE-2017-0002', save=True) -> CveDocument:
    cve = CveDocument(
        id=cve_id,
        base_score_v2=6.8,
        access_vector_v2=metrics.AccessVectorV2.NETWORK,
        access_complexity_v2=metrics.AccessComplexityV2.MEDIUM,
        authentication_v2=metrics.AuthenticationV2.NONE,
        confidentiality_impact_v2=metrics.ImpactV2.PARTIAL,
        integrity_impact_v2=metrics.ImpactV2.PARTIAL,
        availability_impact_v2=metrics.ImpactV2.PARTIAL,
        base_score_v3=8.8,
        attack_vector_v3=metrics.AttackVectorV3.NETWORK,
        attack_complexity_v3=metrics.AttackComplexityV3.LOW,
        privileges_required_v3=metrics.PrivilegesRequiredV3.NONE,
        user_interaction_v3=metrics.UserInteractionV3.REQUIRED,
        scope_v3=metrics.ScopeV3.UNCHANGED,
        confidentiality_impact_v3=metrics.ImpactV3.HIGH,
        integrity_impact_v3=metrics.ImpactV3.HIGH,
        availability_impact_v3=metrics.ImpactV3.HIGH
    )
    if save:
        cve.save()
    return cve


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CWEFactoryTest(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        with open(get_fixture_location(__file__, 'cwec_v2.12.xml')) as handle:
            CWEFactory.process(handle)
        thread_pool_executor.wait_for_all()

    def test_should_create_cwe_entries(self):
        result = CweDocument.search().filter('term', id='CWE-1004').execute()
        self.assertEqual(len(result.hits), 1)

        uut = result.hits[0]

        self.assertEqual(uut.id, 'CWE-1004')
        self.assertEqual(uut.name, "Sensitive Cookie Without 'HttpOnly' Flag")
        self.assertEqual(uut.status, "Incomplete")
        self.assertEqual(uut.weakness_abstraction, "Variant")
        self.assertEqual(uut.description, "The software uses a cookie to store sensitive information, "
                                           "but the cookie is not marked with the HttpOnly flag.")
        self.assertEqual(uut.extended_description,
                         "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing "
                         "cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate "
                         "the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might "
                         "attempt to read the contents of a cookie and exfiltrate information obtained. When set, "
                         "browsers that support the flag will not reveal the contents of the cookie to a third party "
                         "via client-side script executed via XSS.")

    def test_should_not_update(self):
        self.assertEqual(Search().index(CweDocument.Index.name).count(), 2)
        with open(get_fixture_location(__file__, 'cwec_v2.12.xml')) as handle:
            CWEFactory.process(handle)
        thread_pool_executor.wait_for_all()
        self.assertEqual(Search().index(CweDocument.Index.name).count(), 2)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CveFactoryTest(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory.process(handle)

        thread_pool_executor.wait_for_all()

    def test_cve_count(self):
        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)

    def test_call_call_not_create_rejected(self):
        self.assertFalse(CveDocument.search().filter('term', id='CVE-2017-0605').execute())

    def test_call_call_not_update(self):
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017-2.json')) as handle:
            CveFactory.process(handle)

        thread_pool_executor.wait_for_all()

        result = CveDocument.search().filter('term', id='CVE-2017-0002').execute()

        self.assertEqual(len(result.hits), 1)
        cve = result.hits[0]
        self.assertEqual(cve.id, 'CVE-2017-0002')
        self.assertEqual(cve.access_vector_v2, metrics.AccessVectorV2.NETWORK)
        self.assertEqual(cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM)
        self.assertEqual(cve.authentication_v2, metrics.AuthenticationV2.NONE)
        self.assertEqual(cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(cve.integrity_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(cve.availability_impact_v2, metrics.ImpactV2.PARTIAL)

    def test_call_create(self):
        cve = CveDocument.search().filter('term', id='CVE-2017-0008').execute().hits[0]
        self.assertEqual(cve.base_score_v2, 4.3)
        self.assertEqual(cve.base_score_v3, 4.3)

        self.assertEqual(
            cve.summary, 'Microsoft Internet Explorer 9 through 11 allow remote attackers to obtain sensitive '
                         'information from process memory via a crafted web site, aka "Internet Explorer Information '
                         'Disclosure Vulnerability." This vulnerability is different from those described in '
                         'CVE-2017-0009 and CVE-2017-0059.')
        self.assertEqual(str(cve.published_date), '2017-03-17 00:59:00+00:00')
        self.assertEqual(str(cve.last_modified_date), '2017-07-12 01:29:00+00:00')

        self.assertEqual(cve.cwe.id, 'CWE-200')
        self.assertEqual(len(cve.cpe), 3)
        self.assertEqual(cve.cpe, [
            {'name': 'cpe:2.3:a:microsoft:internet_explorer:9:*:*:*:*:*:*:*', 'vendor': 'microsoft'},
            {'name': 'cpe:2.3:a:microsoft:internet_explorer:10:*:*:*:*:*:*:*', 'vendor': 'microsoft'},
            {'name': 'cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*', 'vendor': 'microsoft'}
        ])

        self.assertEqual(cve.access_vector_v2, metrics.AccessVectorV2.NETWORK)
        self.assertEqual(cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM)
        self.assertEqual(cve.authentication_v2, metrics.AuthenticationV2.NONE)
        self.assertEqual(cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL)
        self.assertEqual(cve.integrity_impact_v2, metrics.ImpactV2.NONE)
        self.assertEqual(cve.availability_impact_v2, metrics.ImpactV2.NONE)

        self.assertEqual(cve.attack_vector_v3, metrics.AttackVectorV3.NETWORK)
        self.assertEqual(cve.attack_complexity_v3, metrics.AttackComplexityV3.LOW)
        self.assertEqual(cve.privileges_required_v3, metrics.PrivilegesRequiredV3.NONE)
        self.assertEqual(cve.user_interaction_v3, metrics.UserInteractionV3.REQUIRED)
        self.assertEqual(cve.scope_v3, metrics.ScopeV3.UNCHANGED)
        self.assertEqual(cve.confidentiality_impact_v3, metrics.ImpactV3.LOW)
        self.assertEqual(cve.integrity_impact_v3, metrics.ImpactV3.NONE)
        self.assertEqual(cve.availability_impact_v3, metrics.ImpactV3.NONE)

        self.assertEqual(cve.get_privileges_required_v3_value(), 0.85)

    def test_update(self):
        cve = CveDocument.search().filter('term', id='CVE-2017-0002').execute().hits[0]
        cve.last_modified_date = None
        cve.save(refresh=True)

        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory.process(handle)
        thread_pool_executor.wait_for_all()

        self.assertEqual(CveDocument.search().filter('term', id='CVE-2017-0002').count(), 1)
        new_cve = CveDocument.search().filter('term', id='CVE-2017-0002').execute().hits[0]
        self.assertTrue(cve.last_modified_date != new_cve.last_modified_date)

    def test_cwe_update(self):
        cwe = CweDocument.search().filter('term', id='CWE-200').execute().hits[0]
        cwe.name = 'Changed'
        cwe.save()
        thread_pool_executor.wait_for_all()

        self.assertEqual(CveDocument.search().filter('term', id='CVE-2017-0008').count(), 1)
        cve = CveDocument.search().filter('term', id='CVE-2017-0008').execute().hits
        self.assertEqual(len(cve), 1)
        self.assertEqual(cve[0].cwe.name, 'Changed')

    def test_should_not_update(self):
        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)

        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory.process(handle)
        thread_pool_executor.wait_for_all()

        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)

    def test_calculate_base_score(self):
        for cve in CveDocument.search():
            self.assertEqual(cve.base_score_v2, calculate_base_score_v2(cve), cve.id)
            self.assertEqual(cve.base_score_v3, calculate_base_score_v3(cve), cve.id)

    @parameterized.expand([
        (metrics.PrivilegesRequiredV3.NONE, metrics.ScopeV3.CHANGED, Decimal('0.85')),
        (metrics.PrivilegesRequiredV3.NONE, metrics.ScopeV3.UNCHANGED, Decimal('0.85')),
        (metrics.PrivilegesRequiredV3.LOW, metrics.ScopeV3.CHANGED, Decimal('0.68')),
        (metrics.PrivilegesRequiredV3.LOW, metrics.ScopeV3.UNCHANGED, Decimal('0.62')),
        (metrics.PrivilegesRequiredV3.HIGH, metrics.ScopeV3.CHANGED, Decimal('0.50')),
        (metrics.PrivilegesRequiredV3.HIGH, metrics.ScopeV3.UNCHANGED, Decimal('0.27'))
    ])
    def test_privileges_required_V3(self, pr, scope, expected):
        self.assertEqual(pr.value_with_scope(scope), expected)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateCweTaskTest(ESTestCase, TestCase):

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call(self, get_file):
        file = open(get_fixture_location(__file__, 'cwec_v2.12.xml'))
        get_file.return_value = file

        update_cwe()

        get_file.assert_called_once_with('https://cwe.mitre.org/data/xml/cwec_v2.12.xml.zip')
        self.assertEqual(Search().index(CweDocument.Index.name).count(), 2)

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_nok(self, get_file):
        get_file.return_value = None

        update_cwe()

        self.assertEqual(Search().index(CweDocument.Index.name).count(), 0)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateCveTaskTest(ESTestCase, TestCase):

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call(self, get_file):
        file = open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json'))
        get_file.return_value = file

        update_cve(2017)

        get_file.assert_called_once_with(
            'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz'
        )
        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_nok(self, get_file):
        get_file.return_value = None

        update_cve(2017)

        self.assertEqual(Search().index(CveDocument.Index.name).count(), 0)


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class UpdateExploitsTaskTest(ESTestCase, TestCase):

    def setUp(self):
        super().setUp()
        self.load_data()
        thread_pool_executor.wait_for_all()

    def load_data(self):
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory.process(handle)
        with open(get_fixture_location(__file__, 'via4.json')) as handle:
            self.data = handle.read()

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_update_exploits(self, get_file):
        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)
        get_file.return_value = self.data
        update_exploits()
        get_file.assert_called_once_with('https://www.cve-search.org/feeds/via4.json')

        thread_pool_executor.wait_for_all()
        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)

        cve = CveDocument.search().filter('term', id='CVE-2017-0008').sort('-modified_date').execute().hits[0]
        prev_modified_date = cve.modified_date
        self.assertEqual(len(cve.exploits), 1)
        self.assertEqual(cve.exploits, [{'id': '44904', 'url': 'https://www.exploit-db.com/exploits/44904'}])

        update_exploits()
        thread_pool_executor.wait_for_all()

        self.assertEqual(Search().index(CveDocument.Index.name).count(), 2)
        cve = CveDocument.search().filter('term', id='CVE-2017-0008').sort('-modified_date').execute().hits[0]
        self.assertEqual(cve.modified_date, prev_modified_date)
        self.assertEqual(len(cve.exploits), 1)
        self.assertEqual(cve.exploits, [{'id': '44904', 'url': 'https://www.exploit-db.com/exploits/44904'}])
