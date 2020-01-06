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
from decimal import Decimal
from unittest import skipIf
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, LiveServerTestCase
from django_elasticsearch_dsl.test import ESTestCase
from parameterized import parameterized
from vmc.knowledge_base.documents import ExploitDocument, CveDocument, CweDocument

from vmc.config.test_settings import elastic_configured
from vmc.knowledge_base.cache import NotificationCache
from vmc.knowledge_base.factories import CveFactory, CWEFactory, CpeFactory
from vmc.knowledge_base import models
from vmc.knowledge_base import metrics
from vmc.knowledge_base.utils import calculate_base_score_v2, calculate_base_score_v3
from vmc.knowledge_base.tasks import update_exploits, update_cwe, update_cpe, update_cve

from vmc.common.tests import get_fixture_location


class CWEFactoryTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        with open(get_fixture_location(__file__, 'cwec_v2.12.xml')) as handle:
            CWEFactory.process(handle)

    def test_should_create_cwe_entries(self):
        cwe = models.Cwe.objects.get(id='CWE-1004')

        self.assertEqual(cwe.__str__(), 'CWE-1004')
        self.assertEquals(cwe.name, "Sensitive Cookie Without 'HttpOnly' Flag")
        self.assertEquals(cwe.status, "Incomplete")
        self.assertEquals(cwe.weakness_abstraction, "Variant")
        self.assertEquals(cwe.description, "The software uses a cookie to store sensitive information, "
                                           "but the cookie is not marked with the HttpOnly flag.")
        self.assertEqual(cwe.extended_description,
                         "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing "
                         "cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate "
                         "the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might "
                         "attempt to read the contents of a cookie and exfiltrate information obtained. When set, "
                         "browsers that support the flag will not reveal the contents of the cookie to a third party "
                         "via client-side script executed via XSS.")

    def test_cwe_update(self):
        cwe = models.Cwe.objects.get(id='CWE-1004')
        self.assertFalse(cwe.has_changed)

        cwe.status = 'aaaa'
        self.assertTrue(cwe.has_changed)


class CpeFactoryTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        with open(get_fixture_location(__file__, 'official-cpe-dictionary_v2.2.xml')) as handle:
            CpeFactory.process(handle)

    def setUp(self) -> None:
        self.assertEqual(models.Cpe.objects.count(), 1)

    def test_cpe_str_call(self):
        cpe = models.Cpe(name='NAME')
        self.assertEqual(cpe.__str__(), 'NAME')

        cpe.title = 'TITLE'
        cpe.vendor = 'VENDOR'
        self.assertEqual(cpe.__str__(), 'VENDOR TITLE')

    def test_cpe(self):
        cpe = models.Cpe.objects.get(name='cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*')

        self.assertEquals(cpe.vendor, '1000guess')
        self.assertEquals(cpe.title, '1000 Guess')
        self.assertEquals(json.loads(cpe.references), [
            {
                'name': 'Vendor',
                'url': 'http://www.1000guess.com/'
            },
            {
                'name': 'Advisory',
                'url': 'https://medium.com/coinmonks/attack-on-pseudo-random-number-'
                       'generator-prng-used-in-1000-guess-an-ethereum-lottery-game-7b76655f953d'
            }
        ])


class NotificationCacheTest(TestCase):

    def test_update_cache(self):
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory().process(handle)

        self.assertListEqual(NotificationCache.get(), [('CVE-2017-0008', True), ('CVE-2017-0002', True)])

    def test_not_updated_cve(self):
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory().process(handle)
        NotificationCache.clear()

        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            CveFactory().process(handle)
        self.assertEqual(NotificationCache.get(), [])

    def test_initial_update_test(self):
        NotificationCache.initial_update(not models.Cve.objects.exists())
        self.assertTrue(NotificationCache.is_initial_update())


class CveFactoryTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.uut = CveFactory()
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            cls.uut.process(handle)

    def setUp(self):
        super().setUp()
        self.assertEqual(models.Cve.objects.count(), 2)
        self.assertEqual(self.uut.created, 2)

    def test_call_call_not_create_rejected(self):
        self.assertIsNotNone(models.Cve.objects.filter(id='CVE-2017-0605'))

    def test_call_call_not_update(self):
        cve = models.Cve.objects.get(id='CVE-2017-0002')

        self.assertEqual(cve.__str__(), 'CVE-2017-0002')
        self.assertEqual(cve.access_vector_v2, metrics.AccessVectorV2.NETWORK.value)
        self.assertEqual(cve.get_access_vector_v2_display(), metrics.AccessVectorV2.NETWORK.name)
        self.assertEqual(cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM.value)
        self.assertEqual(cve.authentication_v2, metrics.AuthenticationV2.NONE.value)
        self.assertEqual(cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL.value)
        self.assertEqual(cve.integrity_impact_v2, metrics.ImpactV2.PARTIAL.value)
        self.assertEqual(cve.availability_impact_v2, metrics.ImpactV2.PARTIAL.value)

    def test_call_create(self):
        cve = models.Cve.objects.get(id='CVE-2017-0008')
        self.assertEqual(cve.base_score_v2, 4.3)
        self.assertEqual(cve.base_score_v3, 4.3)

        self.assertEqual(cve.cwe.id, 'CWE-200')
        self.assertEqual(
            cve.summary, 'Microsoft Internet Explorer 9 through 11 allow remote attackers to obtain sensitive '
                         'information from process memory via a crafted web site, aka "Internet Explorer Information '
                         'Disclosure Vulnerability." This vulnerability is different from those described in '
                         'CVE-2017-0009 and CVE-2017-0059.')
        self.assertEquals(str(cve.published_date), '2017-03-17 00:59:00+00:00')
        self.assertEquals(str(cve.last_modified_date), '2017-07-12 01:29:00+00:00')

        self.assertEqual(json.loads(cve.references), [
            {
                'source': 'BID',
                'url': 'http://www.securityfocus.com/bid/96073'
            },
            {
                'source': 'SECTRACK',
                'url': 'http://www.securitytracker.com/id/1038008',
            },
            {
                'source': 'CONFIRM',
                'url': 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0008'
            }
        ])

        self.assertEqual(cve.cpe.count(), 3)
        self.assertEqual(cve.cpe.filter(name='cpe:2.3:a:microsoft:internet_explorer:9:*:*:*:*:*:*:*').count(), 1)
        self.assertEqual(cve.cpe.filter(name='cpe:2.3:a:microsoft:internet_explorer:10:*:*:*:*:*:*:*').count(), 1)
        self.assertEqual(cve.cpe.filter(name='cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*').count(), 1)

        self.assertEqual(cve.access_vector_v2, metrics.AccessVectorV2.NETWORK.value)
        self.assertEqual(cve.access_complexity_v2, metrics.AccessComplexityV2.MEDIUM.value)
        self.assertEqual(cve.authentication_v2, metrics.AuthenticationV2.NONE.value)
        self.assertEqual(cve.confidentiality_impact_v2, metrics.ImpactV2.PARTIAL.value)
        self.assertEqual(cve.integrity_impact_v2, metrics.ImpactV2.NONE.value)
        self.assertEqual(cve.availability_impact_v2, metrics.ImpactV2.NONE.value)

        self.assertEqual(cve.attack_vector_v3, metrics.AttackVectorV3.NETWORK.value)
        self.assertEqual(cve.attack_complexity_v3, metrics.AttackComplexityV3.LOW.value)
        self.assertEqual(cve.privileges_required_v3, metrics.PrivilegesRequiredV3.NONE.value)
        self.assertEqual(cve.user_interaction_v3, metrics.UserInteractionV3.REQUIRED.value)
        self.assertEqual(cve.scope_v3, metrics.ScopeV3.UNCHANGED.value)
        self.assertEqual(cve.confidentiality_impact_v3, metrics.ImpactV3.LOW.value)
        self.assertEqual(cve.integrity_impact_v3, metrics.ImpactV3.NONE.value)
        self.assertEqual(cve.availability_impact_v3, metrics.ImpactV3.NONE.value)

        self.assertEqual(cve.get_privileges_required_v3_value(), 0.85)
        self.assertEqual([('CVE-2017-0008', True), ('CVE-2017-0002', True)], NotificationCache.get())

    def test_update(self):
        cve = models.Cve.objects.get(id='CVE-2017-0008')
        cve.last_modified_date = None
        cve.save()
        cache.clear()
        factory = CveFactory()
        with open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json')) as handle:
            factory.process(handle)

        self.assertEqual([('CVE-2017-0008', False)], NotificationCache.get())
        self.assertEqual(factory.updated, 1)

    def test_calculate_base_score(self):
        for cve in models.Cve.objects.filter(id='CVE-2017-0002'):
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

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cache.clear()


class UpdateCweTaskTest(TestCase):

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call(self, get_file):
        file = open(get_fixture_location(__file__, 'cwec_v2.12.xml'))
        get_file.return_value = file

        update_cwe()

        get_file.assert_called_once_with('https://cwe.mitre.org/data/xml/cwec_v2.12.xml.zip')
        self.assertEqual(models.Cwe.objects.count(), 2)

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_nok(self, get_file):
        get_file.return_value = None

        update_cwe()

        self.assertEqual(models.Cwe.objects.count(), 0)


class UpdateCpeTaskTest(TestCase):

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call(self, get_file):
        file = open(get_fixture_location(__file__, 'official-cpe-dictionary_v2.2.xml'))
        get_file.return_value = file

        update_cpe()

        get_file.assert_called_once_with(
            'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip'
        )
        self.assertEqual(models.Cpe.objects.count(), 1)

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_nok(self, get_file):
        get_file.return_value = None

        update_cpe()

        self.assertEqual(models.Cpe.objects.count(), 0)


class UpdateCveTaskTest(TestCase):

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call(self, get_file):
        file = open(get_fixture_location(__file__, 'nvdcve-1.0-2017.json'))
        get_file.return_value = file

        update_cve(2017)

        get_file.assert_called_once_with(
            'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.json.gz'
        )
        self.assertEqual(models.Cve.objects.count(), 2)

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_nok(self, get_file):
        get_file.return_value = None

        update_cve(2017)

        self.assertEqual(models.Cve.objects.count(), 0)


class UpdateExploitsTaskTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        with open(get_fixture_location(__file__, 'via4.json')) as handle:
            cls.data = handle.read()

    @patch('vmc.knowledge_base.tasks.get_file')
    def test_call_update_exploits(self, get_file):
        get_file.return_value = self.data
        update_exploits()
        get_file.assert_called_once_with('https://www.cve-search.org/feeds/via4.json')

        cve = models.Cve.objects.get(id='CVE-2018-12326')
        self.assertEqual(cve.exploits.count(), 1)
        self.assertIsNotNone(cve.exploits.get(id='44904'))

        cve = models.Cve.objects.get(id='CVE-2018-12326')
        self.assertEqual(cve.exploits.count(), 1)
        self.assertIsNotNone(cve.exploits.get(id='44904'))
        self.assertEqual(models.Cve.history.count(), 1)


class AdminPanelTest(LiveServerTestCase):
    fixtures = ['users.json']

    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.get(username='admin'))

    @parameterized.expand([
        ('/admin/knowledge_base/cve/', 'nvd-cve-import'),
        ('/admin/knowledge_base/cpe/', 'nvd-cpe-import')
    ])
    def test_button_exists(self, url, expected):
        self.assertContains(self.client.get(url), expected)

    @patch('vmc.knowledge_base.admin.update_cve_cwe')
    def test_call_update_cve(self, update_cve_cwe):
        response = self.client.get('/admin/knowledge_base/cve/import', follow=True)
        update_cve_cwe.delay.assert_called_once()
        self.assertContains(response, 'Importing started.')

    @patch('vmc.knowledge_base.admin.update_cpe')
    def test_call_update_cpe(self, update_cpe):
        response = self.client.get('/admin/knowledge_base/cpe/import', follow=True)
        update_cpe.delay.assert_called_once()
        self.assertContains(response, 'Importing started.')

    def tearDown(self):
        self.client.logout()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CveDocumentTest(ESTestCase, TestCase):

    def test_model_class_added(self):
        self.assertEqual(CveDocument.Django.model, models.Cve)

    def test_document_index_name(self):
        self.assertEqual(CveDocument.Index.name, 'cve')

    def test_related_models(self):
        self.assertEqual(CveDocument.Django.related_models, [models.Cwe, models.Cpe, models.Exploit])

    def test_document(self):
        cve = CveDocumentTest.create_cve()
        search = CveDocument.search().filter('term', id=cve.id).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.id, cve.id)
        self.assertEqual(uut.base_score_v2, cve.base_score_v2)
        self.assertEqual(uut.base_score_v3, cve.base_score_v3)
        self.assertEqual(uut.summary, cve.summary)
        self.assertEqual(uut.access_vector_v2, cve.get_access_vector_v2_display())
        self.assertEqual(uut.access_complexity_v2, cve.get_access_complexity_v2_display())
        self.assertEqual(uut.authentication_v2, cve.get_authentication_v2_display())
        self.assertEqual(uut.confidentiality_impact_v2, cve.get_confidentiality_impact_v2_display())
        self.assertEqual(uut.integrity_impact_v2, cve.get_integrity_impact_v2_display())
        self.assertEqual(uut.availability_impact_v2, cve.get_availability_impact_v2_display())

        self.assertEqual(uut.attack_vector_v3, cve.get_attack_vector_v3_display())
        self.assertEqual(uut.attack_complexity_v3, cve.get_attack_complexity_v3_display())
        self.assertEqual(uut.privileges_required_v3, cve.get_privileges_required_v3_display())
        self.assertEqual(uut.user_interaction_v3, cve.get_user_interaction_v3_display())
        self.assertEqual(uut.scope_v3, cve.get_scope_v3_display())
        self.assertEqual(uut.confidentiality_impact_v3, cve.get_confidentiality_impact_v3_display())
        self.assertEqual(uut.integrity_impact_v3, cve.get_integrity_impact_v3_display())
        self.assertEqual(uut.availability_impact_v3, cve.get_availability_impact_v3_display())

        self.assertEqual(uut.cwe.id, cve.cwe.id)
        self.assertEqual(uut.cwe.name, cve.cwe.name)
        self.assertEqual(uut.cwe.description, cve.cwe.description)

        self.assertEqual(len(uut.exploits), cve.exploits.count())
        self.assertEqual(uut.exploits[0].id, cve.exploits.first().id)
        self.assertEqual(uut.exploits[0].url, cve.exploits.first().url)

    @staticmethod
    def create_cve() -> models.Cve:
        cve = models.Cve.objects.create(
            id='CVE-2017-0002',
            cwe=CweDocumentTest.create_cwe(),
            base_score_v2=3.1,
            base_score_v3=3.2,
            summary='SUMMARY',
            access_vector_v2=metrics.AccessComplexityV2.LOW.value,
            access_complexity_v2=metrics.AccessComplexityV2.HIGH.value,
            authentication_v2=metrics.AuthenticationV2.SINGLE.value,
            confidentiality_impact_v2=metrics.ImpactV2.NONE.value,
            integrity_impact_v2=metrics.ImpactV2.PARTIAL.value,
            availability_impact_v2=metrics.ImpactV2.COMPLETE.value,
            attack_vector_v3=metrics.AttackVectorV3.LOCAL.value,
            attack_complexity_v3=metrics.AttackComplexityV3.LOW.value,
            privileges_required_v3=metrics.PrivilegesRequiredV3.HIGH.value,
            user_interaction_v3=metrics.UserInteractionV3.REQUIRED.value,
            scope_v3=metrics.ScopeV3.CHANGED.value,
            confidentiality_impact_v3=metrics.ImpactV3.HIGH.value,
            integrity_impact_v3=metrics.ImpactV3.LOW.value,
            availability_impact_v3=metrics.ImpactV3.NONE.value,
        )
        cve.exploits.add(ExploitDocumentTest.create_exploit())
        return cve

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cache.clear()


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class CweDocumentTest(ESTestCase, TestCase):
    CWE_ID = 'CWE-100'
    CWE_NAME = 'CWE-NAME'
    CWE_STATUS = 'CWE-STATUS'
    CWE_WEAKNESS_ABSTRACTION = 'CWE-WEAKNESS_ABSTRACTION'
    CWE_DESC = 'CWE-DESC'
    CWE_EXT_DESC = 'CWE-EXT-DESC'

    def test_model_class_added(self):
        self.assertEqual(CweDocument.Django.model, models.Cwe.history.model)

    def test_document_index_name(self):
        self.assertEqual(CweDocument.Index.name, 'cwe')

    def test_document(self):
        cwe = self.create_cwe()
        search = CweDocument.search().filter('term', id=CweDocumentTest.CWE_ID).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.id, CweDocumentTest.CWE_ID)
        self.assertEqual(uut.name, CweDocumentTest.CWE_NAME)
        self.assertEqual(uut.status, CweDocumentTest.CWE_STATUS)
        self.assertEqual(uut.weakness_abstraction, CweDocumentTest.CWE_WEAKNESS_ABSTRACTION)
        self.assertEqual(uut.description, CweDocumentTest.CWE_DESC)
        self.assertEqual(uut.extended_description, CweDocumentTest.CWE_EXT_DESC)
        self.assertTrue(uut.created_date)
        self.assertTrue(uut.modified_date)
        prev_date = uut.modified_date

        cwe.description = 'new description'
        cwe.save()

        search = CweDocument.search().filter('term', id=CweDocumentTest.CWE_ID).execute()
        self.assertEqual(len(search.hits), 2)

        uut = search.hits[1]
        self.assertEqual(uut.description, 'new description')
        self.assertNotEqual(uut.modified_date, prev_date)
        self.assertEqual(uut.id, CweDocumentTest.CWE_ID)

    @staticmethod
    def create_cwe() -> models.Cwe:
        return models.Cwe.objects.create(
            id=CweDocumentTest.CWE_ID,
            name=CweDocumentTest.CWE_NAME,
            status=CweDocumentTest.CWE_STATUS,
            weakness_abstraction=CweDocumentTest.CWE_WEAKNESS_ABSTRACTION,
            description=CweDocumentTest.CWE_DESC,
            extended_description=CweDocumentTest.CWE_EXT_DESC
        )


@skipIf(not elastic_configured(), 'Skip if elasticsearch is not configured')
class ExploitDocumentTest(ESTestCase, TestCase):

    def test_model_class_added(self):
        self.assertEqual(ExploitDocument.django.model, models.Exploit)

    def test_document_index_name(self):
        self.assertEqual(ExploitDocument.Index.name, 'exploit')

    def test_document(self):
        self.create_exploit()
        search = ExploitDocument.search().filter('term', id=1).execute()
        self.assertEqual(len(search.hits), 1)

        uut = search.hits[0]
        self.assertEqual(uut.id, 1)
        self.assertEqual(uut.url, 'https://www.exploit-db.com/exploits/1')
        self.assertTrue(uut.created_date)
        self.assertTrue(uut.modified_date)

    @staticmethod
    def create_exploit() -> models.Exploit:
        return models.Exploit.objects.create(id=1)
