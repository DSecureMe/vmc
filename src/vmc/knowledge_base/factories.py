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
from django.utils.dateparse import parse_datetime
from vmc.knowledge_base.documents import CweDocument, CveDocument, CpeDocument, ExploitDocument

from vmc.common.xml import iter_elements_by_name
from vmc.knowledge_base import metrics


class CWEFactory:

    @staticmethod
    def process(handle):
        for obj in iter_elements_by_name(handle, 'Weakness'):
            CWEFactory.create(obj)

    @staticmethod
    def create(item: RestrictedElement):
        cwe_id = 'CWE-{}'.format(item.get('ID'))

        old = CweDocument.search().filter('term', id=cwe_id).sort('-modified_date')[0].execute()
        cwe = CweDocument(id=cwe_id)
        for field in CweDocument.get_fields_name():
            parser = getattr(CWEFactory, field, None)
            if parser:
                setattr(cwe, field, parser(item))

        if old.hits and cwe.has_changed(old.hits[0]):
            cwe.created_date = old.hits[0].created_date
            cwe.save(refresh=True)
        elif not old.hits:
            cwe.save(refresh=True)

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


class CpeFactory:
    VENDOR = 1

    @staticmethod
    def get(name: str) -> CpeDocument:
        return CpeDocument(name=name, vendor=CpeFactory.get_field(name.replace('cpe:2.3:', ''), CpeFactory.VENDOR))

    @staticmethod
    def get_field(soft: str, idx: int) -> [str, None]:
        soft = soft.replace('cpe:/', '').split(':')
        return soft[idx] if len(soft) > idx else None


class CveFactory:
    FIELDS = [i for i in CveDocument.get_fields_name()]

    @staticmethod
    def process(handle):
        data = json.load(handle)
        for obj in data['CVE_Items']:
            CveFactory.create(obj)  # FIXME: bulk create

    @staticmethod
    def create(item: dict):
        if '** REJECT **' not in CveFactory.summary(item):
            old = CveDocument.search().filter(
                'term', id=CveFactory.get_id(item)).sort('-last_modified_date')[0].execute()
            if old.hits:
                last_modified_date = old.hits[0].last_modified_date
            else:
                last_modified_date = None

            if not last_modified_date or last_modified_date < CveFactory.last_modified_date(item):
                cve = CveDocument(id=CveFactory.get_id(item))
                for field in CveDocument.get_fields_name():
                    parser = getattr(CveFactory, field, None)
                    if parser:
                        try:
                            setattr(cve, field, parser(item))
                        except Exception as err:
                            logging.debug('cve id %s, field %s, err %s', cve.id, field, err)

                for cpe in CveFactory.get_cpe(item):
                    cve.cpe.append(cpe)

                if old.hits and cve.has_changed(old.hits[0]):
                    cve.modified_date = old.hits[0].modified_date
                    cve.save(refresh=True)
                else:
                    cve.save(refresh=True)
            return None

        logging.info('cve id %s is rejected', CveFactory.get_id(item))
        return None

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
    def get_cpe(item: dict) -> list:
        cpes = []
        try:
            for conf in item['configurations']['nodes']:
                for cpe_match in conf['cpe_match']:
                    cpes.append(CpeFactory.get(cpe_match['cpe23Uri']))
        except (KeyError, IndexError):
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
            # FIXME: create new cve ?
            result = CveDocument.search().filter('term', id=key).sort('-last_modified_date')[0].execute()
            if result.hits:
                result.hits[0].exploits = []
                for exp_id in value['refmap']['exploit-db']:
                    result.hits[0].exploits.append(ExploitDocument.create(exp_id=exp_id))
                    result.hits[0].save(refresh=True)
        except KeyError:
            pass
