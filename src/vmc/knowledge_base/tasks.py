# -*- coding: utf-8 -*-
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

from __future__ import absolute_import, unicode_literals

import logging

from datetime import datetime

from celery import shared_task, group

from vmc.common.utils import get_file
from vmc.knowledge_base.factories import CveFactory, CWEFactory, ExploitFactory


START_YEAR = 2002
CVE_NVD_URL = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{}.json.gz'
CWE_MITRE_URL = 'https://cwe.mitre.org/data/xml/cwec_v2.12.xml.zip'
VIA4_URL = 'https://www.cve-search.org/feeds/via4.json'

LOGGER = logging.getLogger(__name__)


@shared_task
def update_cwe():
    try:
        LOGGER.info('Updating cws, download file')
        file = get_file(CWE_MITRE_URL)
        if file:
            LOGGER.info('File downloaded for cwe year, parsing...')
            CWEFactory.process(file)
            file.close()
            LOGGER.info('CWE file parsing done.')
        else:
            LOGGER.info('Unable to download CWE file')
    except Exception as ex:
        LOGGER.error(ex)


@shared_task
def update_cve(year: int):
    try:
        LOGGER.info('Trying to get file for %d year', year)
        file = get_file(CVE_NVD_URL.format(year))
        if file:
            LOGGER.info('File downloaded for %d year, parsing...', year)
            CveFactory.process(file)
            file.close()
            LOGGER.info('Parsing for %d, done.', year)
        else:
            LOGGER.info('Unable to download file for %d year', year)
    except Exception as ex:
        LOGGER.error(ex)


@shared_task
def update_exploits():
    try:
        LOGGER.info('Trying to get %s', VIA4_URL)
        file = get_file(VIA4_URL)
        if file:
            LOGGER.info('File downloaded, updating database.')
            ExploitFactory.process(file)
            LOGGER.info('Database updated')
        else:
            LOGGER.error('Unable do download file %s', VIA4_URL)
    except Exception as ex:
        LOGGER.error(ex)


@shared_task
def update_cve_cwe():
    (
        group(update_cve.si(year) for year in range(START_YEAR, datetime.now().year + 1)) |
        update_cwe.si() |
        update_exploits.si()
    )()
