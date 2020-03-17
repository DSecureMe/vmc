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
import datetime

from typing import Dict

from celery import shared_task

from vmc.common.tasks import memcache_lock

from vmc.nessus.api import Nessus
from vmc.nessus.models import Config
from vmc.nessus.parsers import ReportParser

from vmc.vulnerabilities.documents import VulnerabilityDocument

TRASH_FOLDER_TYPE = 'trash'
LOGGER = logging.getLogger(__name__)


def get_trash_folder_id(scan_list: Dict) -> [int, None]:
    if 'folders' in scan_list:
        for folder in scan_list['folders']:
            if folder['type'] == TRASH_FOLDER_TYPE:
                return folder['id']
    return None


def calculate_epoch_from_interval(interval: int) -> int:
    return int(datetime.datetime.now().timestamp()) - (interval*60)


def _update(config: Config, scan_id: int, scanner_api=Nessus):
    try:
        api = scanner_api(config)
        LOGGER.info(F'Trying to download nessus file {scan_id}')
        file = api.download_scan(scan_id)
        if file:
            LOGGER.info(F'Trying to parse nessus file {scan_id}')
            parser = ReportParser(config)
            vulns, scanned_hosts = parser.parse(file)
            file.close()
            LOGGER.info(F'Nessus file parsed: {scan_id}')
            LOGGER.info(F'Attempting to update vulns data in {config}')
            VulnerabilityDocument.create_or_update(vulns, scanned_hosts, config)
        else:
            LOGGER.error('Unable to download nessus file')

    except Exception as e:
        import traceback
        traceback.print_exc()
        LOGGER.error(F"Error while loading vulnerabiltiy data {e}")


@shared_task
def update_data(config_pk: int, scan_id: int, scanner_api=Nessus):  # pylint: disable=too-many-locals
    config = Config.objects.get(pk=config_pk)
    lock_id = F"update-vulnerabilities-loc-{config.id}"
    with memcache_lock(lock_id, config) as acquired:
        if acquired:
            return _update(config, scan_id, scanner_api)
    LOGGER.info(F"Vulnerability update for {config.name} is already being done by another worker")


@shared_task
def update(scanner_api=Nessus): #TODO: implement memcach_lock
    for config in Config.objects.all():
        con = scanner_api(config)
        scan_list = con.get_scan_list(last_modification_date=calculate_epoch_from_interval(config.update_interval))

        if scan_list:
            trash_folder_id = get_trash_folder_id(scan_list)

            for scan in scan_list['scans']:
                if scan['folder_id'] != trash_folder_id:
                    LOGGER.debug('scan_id %d scan_name %s from %s', scan['id'], scan['name'], config.name)
                    update_data.delay(config_pk=config.pk, scan_id=int(scan['id']))
        else:
            LOGGER.info('Scan list is empty')
