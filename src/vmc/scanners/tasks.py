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
from vmc.processing.tasks import start_processing
from vmc.assets.documents import AssetDocument, AssetStatus


LOGGER = logging.getLogger(__name__)


def _update_scans(config: Config):
    try:
        client, parser = scanners_registry.get(config)

        now_date = now()
        scan_list = client.get_scans(last_modification_date=config.last_scans_pull)
        scan_list = parser.get_scans_ids(scan_list)
        for scan_id in scan_list:
            LOGGER.info(F'Trying to download report form {config.name}')
            file = client.download_scan(scan_id)
            LOGGER.info(F'Retreiving discovered assets for {config.name}')
            discovered_assets = AssetDocument.get_assets_with_tag(tag=AssetStatus.DISCOVERED, config=config)
            LOGGER.info(F'Trying to parse scan file {scan_id}')
            vulns, scanned_hosts = parser.parse(file)
            LOGGER.info(F'File parsed: {scan_id}')
            LOGGER.info(F'Trying to parse targets from file {scan_id}')
            get_target_method = getattr(client, "get_targets", parser.get_targets)
            targets = get_target_method(file)
            LOGGER.info(F'Targets parsed: {scan_id}')
            LOGGER.info(F'Attempting to update discovered assets in {config.name}')
            AssetDocument.update_gone_discovered_assets(targets=targets, scanned_hosts=scanned_hosts,
                                                        discovered_assets=discovered_assets, config=config)
            LOGGER.info(F'Attempting to update vulns data in {config.name}')
            VulnerabilityDocument.create_or_update(vulns, scanned_hosts, config)
        config.last_scans_pull = now_date
        config.save()

        return True

    except Exception as e:
        import traceback
        traceback.print_exc()
        LOGGER.error(F'Error while loading vulnerability data {e}')

    return False


@shared_task(trail=True)
def update_scans(config_pk: int):
    config = Config.objects.get(pk=config_pk)
    lock_id = F'update-vulnerabilities-loc-{config_pk}'
    with memcache_lock(lock_id, config.id) as acquired:
        if acquired:
            return _update_scans(config)
    LOGGER.info(F'Vulnerability update for {config.name} is already being done by another worker')
    return False


@shared_task
def update():
    configs = Config.objects.all().values_list('id', flat=True)
    (
        group(update_scans.si(config_pk=config) for config in configs) |
        start_processing.si()
    )()
