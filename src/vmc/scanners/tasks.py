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
from django.utils.timezone import now

from celery import shared_task, group

from vmc.common.tasks import memcache_lock
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.vulnerabilities.documents import VulnerabilityDocument

LOGGER = logging.getLogger(__name__)


def _update_scan(config: Config, scan_id: int):
    try:
        client, parser = scanners_registry.get(config)

        LOGGER.info(F'Trying to download report form {config.name}')
        file = client.download_scan(scan_id)

        LOGGER.info(F'Trying to parse scan file {scan_id}')
        vulns, scanned_hosts = parser.parse(file)

        LOGGER.info(F'File parsed: {scan_id}')
        LOGGER.info(F'Attempting to update vulns data in {config.name}')
        VulnerabilityDocument.create_or_update(vulns, scanned_hosts, config)
        return True

    except Exception as e:
        import traceback
        traceback.print_exc()
        LOGGER.error(F'Error while loading vulnerability data {e}')

    return False


@shared_task(trail=True)
def update_scan(config_pk: int, scan_id: int):
    config = Config.objects.get(pk=config_pk)
    lock_id = F'update-vulnerabilities-loc-{scan_id}'
    with memcache_lock(lock_id, config.id) as acquired:
        if acquired:
            return _update_scan(config, scan_id)
    LOGGER.info(F'Vulnerability update for {config.name} is already being done by another worker')
    return False


@shared_task
def update_last_scans_pull(result, config_pk: int, date):
    config = Config.objects.get(pk=config_pk)
    if all(result):
        config.last_scans_pull = date
        config.save()


@shared_task
def update():
    for config in Config.objects.all():
        try:
            client, parser = scanners_registry.get(config)

            now_date = now()
            scan_list = client.get_scans(last_modification_date=config.last_scans_pull)
            scan_list = parser.get_scans_ids(scan_list)

            scans = group(update_scan.si(config_pk=config.pk, scan_id=scan_id) for scan_id in scan_list)
            chain = scans | update_last_scans_pull.s(config.id, now_date)
            chain()

        except Exception as e:
            import traceback
            traceback.print_exc()
            LOGGER.error(F"Error while loading vulnerability data {e}")

