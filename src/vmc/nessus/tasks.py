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

from typing import Dict

from celery import shared_task

from vmc.assets.models import Asset, Port
from vmc.nessus.api import Nessus
from vmc.nessus.models import Config
from vmc.nessus.parsers import ReportParser
from vmc.vulnerabilities.models import Vulnerability

TRASH_FOLDER_TYPE = 'trash'
LOGGER = logging.getLogger(__name__)


def get_trash_folder_id(scan_list: Dict) -> [int, None]:
    if 'folders' in scan_list:
        for folder in scan_list['folders']:
            if folder['type'] == TRASH_FOLDER_TYPE:
                return folder['id']
    return None


@shared_task
def update_data(config_pk: int, scan_id: int, scaner_api=Nessus):  # pylint: disable=too-many-locals
    api = scaner_api(Config.objects.get(pk=config_pk))
    LOGGER.info('Trying to download nessus file %d', scan_id)
    file = api.download_scan(scan_id)
    if file:
        LOGGER.info('Trying to parse nessus file %d', scan_id)
        ReportParser.parse(file)
        file.close()
        LOGGER.info('Parsing nessus file %d done.', scan_id)
    else:
        LOGGER.error('Unable to download nessus file')


def cleanup_assets():
    LOGGER.info('Removing all host and ports')
    Vulnerability.objects.all().delete()
    Asset.objects.all().delete()
    Port.objects.all().delete()
    LOGGER.info('All host and ports removed')


@shared_task
def update(scanner_api=Nessus):
    cleanup_assets()

    for config in Config.objects.all():
        con = scanner_api(config)
        scan_list = con.get_scan_list()

        if scan_list:
            trash_folder_id = get_trash_folder_id(scan_list)

            for scan in scan_list['scans']:
                if scan['folder_id'] != trash_folder_id:
                    LOGGER.debug('scan_id %d scan_name %s from %s' , scan['id'], scan['name'], config.name)
                    update_data.delay(config_pk=config.pk, scan_id=int(scan['id']))
        else:
            LOGGER.info('Scan list is empty')
