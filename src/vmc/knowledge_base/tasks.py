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

from vmc.common.tasks import start_workflow
from vmc.common.utils import thread_pool_executor
from vmc.common.utils import get_file
from vmc.processing.tasks import start_processing
from vmc.knowledge_base.factories import CveFactory, CWEFactory, ExploitFactory


START_YEAR = 2002
CVE_NVD_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz'
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
    finally:
        thread_pool_executor.wait_for_all()


@shared_task
def update_cve(year: int):
    try:
        LOGGER.info(F'Trying to get file for {year} year')
        file = get_file(CVE_NVD_URL.format(year))
        if file:
            LOGGER.info(F'File downloaded for {year} year, parsing...')
            CveFactory.process(file)
            file.close()
            LOGGER.info(F'Parsing for {year}, done.')
        else:
            LOGGER.info(F'Unable to download file for {year} year')
    except Exception as ex:
        LOGGER.error(ex)
    finally:
        thread_pool_executor.wait_for_all()


@shared_task
def update_exploits():
    try:
        LOGGER.info(F'Trying to get {VIA4_URL}')
        file = get_file(VIA4_URL)
        if file:
            LOGGER.info('File downloaded, updating database.')
            ExploitFactory.process(file)
            LOGGER.info('Database updated')
        else:
            LOGGER.error(F'Unable do download file {VIA4_URL}')
    except Exception as ex:
        LOGGER.error(ex)
    finally:
        thread_pool_executor.wait_for_all()


@shared_task(name='Update knowledge base')
def start_update_knowledge_base():
    workflow = (
            group(
                update_cwe.si() |
                group(update_cve.si(year) for year in range(START_YEAR, datetime.now().year + 1)) |
                update_exploits.si()
            ) |
            start_processing.si()
    )
    return start_workflow(workflow, global_lock=True)
