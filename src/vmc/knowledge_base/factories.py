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
from datetime import datetime

from defusedxml.lxml import RestrictedElement
from django.core.exceptions import ObjectDoesNotExist
from django.utils.dateparse import parse_datetime

from vmc.common.xml import iter_elements_by_name
from vmc.knowledge_base import models
from vmc.knowledge_base import metrics


class CWEFactory:
    FIELD_LIST = [field.name for field in models.Cwe._meta.get_fields() if field]

    @staticmethod
    def process(handle):
        for obj in iter_elements_by_name(handle, 'Weakness'):
            CWEFactory.create(obj)

    @staticmethod
    def create(item: RestrictedElement) -> models.Cwe:
        cwe_id = 'CWE-{}'.format(item.get('ID'))

        try:
            cwe = models.Cwe.objects.get(id=cwe_id)
        except models.Cwe.DoesNotExist:
            cwe = models.Cwe(id=cwe_id)

        for field in sorted(CWEFactory.FIELD_LIST):
            parser = getattr(CWEFactory, field, None)
            if parser:
                setattr(cwe, field, parser(item))
        if cwe.has_changed:
            cwe.save()
        return cwe

    @staticmethod
    def name(item: RestrictedElement) -> str:
        return item.get('Name')

    @staticmethod
    def weakness_abstraction(item: RestrictedElement) -> str:
        return item.get('Weakness_Abstraction')

    @staticmethod
    def status(item: RestrictedElement) -> str:
        return item.get('Status')

    @staticmethod
    def description(item: RestrictedElement) -> [str, None]:
        desc_item = item.find('Description')

        summary = desc_item.find('Description_Summary')
        if summary is not None:
            return CWEFactory.remove_whitespaces(summary)
        return None

    @staticmethod
    def extended_description(item: RestrictedElement) -> [str, None]:
        desc_item = item.find('Description')
        extended = desc_item.find('Extended_Description')
        if extended is not None:
            text = extended.find('Text')
            if text is not None:
                return CWEFactory.remove_whitespaces(text)
        return None

    @staticmethod
    def remove_whitespaces(item: RestrictedElement) -> str:
        text = item.text.replace('\n', '')
        return ' '.join(text.split())

    @staticmethod
    def get(cwe_id: str) -> models.Cwe:
        cwe, _ = models.Cwe.objects.get_or_create(id=cwe_id)
        return cwe


class CpeFactory:
    VENDOR = 1
    FIELD_LIST = [field.name for field in models.Cpe._meta.get_fields() if field]

    @staticmethod
    def process(handle):
        for obj in iter_elements_by_name(handle, '{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
            CpeFactory.create(obj)

    @staticmethod
    def create(item: RestrictedElement) -> models.Cpe:
        name = item.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').get('name')
        cpe = CpeFactory.get(name)

        for field in sorted(CpeFactory.FIELD_LIST):
            parser = getattr(CpeFactory, field, None)
            if parser:
                setattr(cpe, field, parser(item))

            cpe.save()
        return cpe

    @staticmethod
    def vendor(item: RestrictedElement) -> str:
        return CpeFactory.get_field(item.get('name'), CpeFactory.VENDOR)

    @staticmethod
    def title(item: RestrictedElement) -> str:
        return item.find('{http://cpe.mitre.org/dictionary/2.0}title').text

    @staticmethod
    def references(item: RestrictedElement) -> str:
        references = item.find('{http://cpe.mitre.org/dictionary/2.0}references')
        ref_list = []
        if references is not None:
            for ref in references:
                ref_list.append({
                    'name': ref.text,
                    'url': ref.attrib.get('href')
                })
        return json.dumps(ref_list)

    @staticmethod
    def get(name: str) -> models.Cpe:
        cpe, _ = models.Cpe.objects.get_or_create(
            name=name, vendor=CpeFactory.get_field(name.replace('cpe:2.3:', ''), CpeFactory.VENDOR))
        return cpe

    @staticmethod
    def get_field(soft: str, idx: int) -> [str, None]:
        soft = soft.replace('cpe:/', '').split(':')
        return soft[idx] if len(soft) > idx else None


class CveFactory:
    FIELD_LIST = [field.name for field in models.Cve._meta.get_fields() if field]

    def __init__(self):
        self.created = 0
        self.updated = 0

    def process(self, handle):
        data = json.load(handle)
        for obj in data['CVE_Items']:
            self.create(obj)

    def create(self, item: dict) -> [models.Cve, None]:
        if '** REJECT **' not in CveFactory.summary(item):
            cve, created = self.ger_or_create_new(item)
            if not cve.last_modified_date or cve.last_modified_date < self.last_modified_date(item):
                for field in sorted(CveFactory.FIELD_LIST):
                    parser = getattr(self, field, None)
                    if parser:
                        try:
                            setattr(cve, field, parser(item))
                        except Exception as err:
                            logging.warning('cve id %s, field %s, err %s', cve.id, field, err)
                cve.save()
                cve.cpe.set(self.get_cpe(item))
                if created:
                    self.created += 1
                else:
                    self.updated += 1
            return cve

        logging.info('cve id %s is rejected', CveFactory.get_id(item))
        return None

    @staticmethod
    def ger_or_create_new(item: dict) -> [models.Cve, bool]:
        try:
            return models.Cve.objects.get(id=CveFactory.get_id(item)), False
        except ObjectDoesNotExist:
            return models.Cve(id=CveFactory.get_id(item)), True

    @staticmethod
    def get_id(item: dict) -> str:
        return item['cve']['CVE_data_meta']['ID']

    @staticmethod
    def base_score_v2(item: dict) -> [float, None]:
        return CveFactory.base_score('cvssV2', item)

    @staticmethod
    def base_score_v3(item: dict) -> [float, None]:
        return CveFactory.base_score('cvssV3', item)

    @staticmethod
    def base_score(version: str, item: dict) -> [float, None]:
        score = CveFactory.value_from_base_metrics(version, 'baseScore', item)
        return float(score) if score else None

    @staticmethod
    def summary(item: dict) -> str:
        for desc in item['cve']['description']['description_data']:
            if desc['lang'] == 'en':
                return desc['value']
        return str()

    @staticmethod
    def references(item: RestrictedElement) -> str:
        objs = []
        for ref in item['cve']['references']['reference_data']:
            objs.append({
                'source': ref['refsource'],
                'url': ref['url']
            })
        return json.dumps(objs)

    @staticmethod
    def cwe(item: dict) -> [models.Cwe, None]:
        for problemtype_data in item['cve']['problemtype']['problemtype_data']:
            for desc in problemtype_data['description']:
                if desc['lang'] == 'en':
                    return CWEFactory.get(desc['value'])
        return None

    @staticmethod
    def get_cpe(item: dict) -> list:
        cpes = []
        try:
            for conf in item['configurations']['nodes']:
                for cpe_match in conf['cpe_match']:
                    cpes.append(CpeFactory.get(cpe_match['cpe23Uri']))
        except KeyError:
            pass
        return cpes

    @staticmethod
    def published_date(item: dict) -> datetime:
        return parse_datetime(item['publishedDate'])

    @staticmethod
    def last_modified_date(item: dict) -> datetime:
        return parse_datetime(item['lastModifiedDate'])

    @staticmethod
    def access_vector_v2(item: dict) -> metrics.AccessVectorV2:
        av = CveFactory.value_from_base_metrics('cvssV2', 'accessVector', item)
        return metrics.AccessVectorV2(av).value

    @staticmethod
    def access_complexity_v2(item: dict) -> metrics.AccessComplexityV2:
        ac = CveFactory.value_from_base_metrics('cvssV2', 'accessComplexity', item)
        return metrics.AccessComplexityV2(ac).value

    @staticmethod
    def authentication_v2(item: dict) -> metrics.AuthenticationV2:
        auth = CveFactory.value_from_base_metrics('cvssV2', 'authentication', item)
        return metrics.AuthenticationV2(auth).value

    @staticmethod
    def confidentiality_impact_v2(item: dict) -> metrics.ImpactV2:
        imp = CveFactory.value_from_base_metrics('cvssV2', 'confidentialityImpact', item)
        return metrics.ImpactV2(imp).value

    @staticmethod
    def integrity_impact_v2(item: dict) -> metrics.ImpactV2:
        imp = CveFactory.value_from_base_metrics('cvssV2', 'integrityImpact', item)
        return metrics.ImpactV2(imp).value

    @staticmethod
    def availability_impact_v2(item: dict) -> metrics.ImpactV2:
        imp = CveFactory.value_from_base_metrics('cvssV2', 'availabilityImpact', item)
        return metrics.ImpactV2(imp).value

    @staticmethod
    def attack_vector_v3(item: dict) -> metrics.AttackVectorV3:
        av = CveFactory.value_from_base_metrics('cvssV3', 'attackVector', item)
        return metrics.AttackVectorV3(av).value

    @staticmethod
    def attack_complexity_v3(item: dict) -> metrics.AttackComplexityV3:
        ac = CveFactory.value_from_base_metrics('cvssV3', 'attackComplexity', item)
        return metrics.AttackComplexityV3(ac).value

    @staticmethod
    def privileges_required_v3(item: dict) -> metrics.PrivilegesRequiredV3:
        pr = CveFactory.value_from_base_metrics('cvssV3', 'privilegesRequired', item)
        return metrics.PrivilegesRequiredV3(pr).value

    @staticmethod
    def user_interaction_v3(item: dict) -> metrics.UserInteractionV3:
        us = CveFactory.value_from_base_metrics('cvssV3', 'userInteraction', item)
        return metrics.UserInteractionV3(us).value

    @staticmethod
    def scope_v3(item: dict) -> metrics.ScopeV3:
        sc = CveFactory.value_from_base_metrics('cvssV3', 'scope', item)
        return metrics.ScopeV3(sc).value

    @staticmethod
    def confidentiality_impact_v3(item: dict) -> metrics.ImpactV3:
        ci = CveFactory.value_from_base_metrics('cvssV3', 'confidentialityImpact', item)
        return metrics.ImpactV3(ci).value

    @staticmethod
    def integrity_impact_v3(item: dict) -> metrics.ImpactV3:
        ii = CveFactory.value_from_base_metrics('cvssV3', 'integrityImpact', item)
        return metrics.ImpactV3(ii).value

    @staticmethod
    def availability_impact_v3(item: dict) -> metrics.ImpactV3:
        ai = CveFactory.value_from_base_metrics('cvssV3', 'availabilityImpact', item)
        return metrics.ImpactV3(ai).value

    @staticmethod
    def value_from_base_metrics(version: str, value: str, item: dict) -> [str, None]:
        return item['impact']['baseMetricV2' if version == 'cvssV2' else 'baseMetricV3'][version][value]


class ExploitFactory:

    @staticmethod
    def process(handle):
        data = json.loads(handle)
        for key, value in data['cves'].items():
            ExploitFactory.create(key, value)

    @staticmethod
    def create(key: str, value: dict) -> None:
        try:
            exploit_list = list()
            for exp_id in value['refmap']['exploit-db']:
                e, _ = models.Exploit.objects.get_or_create(id=exp_id)
                exploit_list.append(e)

            cve, _ = models.Cve.objects.get_or_create(id=key)
            cve.exploits.set(exploit_list)

        except KeyError:
            pass
