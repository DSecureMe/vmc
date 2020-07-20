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

import copy
import logging

from django.utils.timezone import now

from celery import shared_task

from vmc.elasticsearch.registries import DocumentRegistry
from vmc.common.utils import thread_pool_executor
from vmc.common.tasks import start_workflow
from vmc.scanners.models import Config
from vmc.scanners.registries import scanners_registry
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.assets.documents import AssetDocument, AssetStatus
from vmc.processing.tasks import start_processing_per_tenant

LOGGER = logging.getLogger(__name__)


@shared_task
def _update_scans(config_pk: int):
    config = Config.objects.filter(pk=config_pk)
    if config.exists():
        config = config.first()
    try:
        config.set_status(Config.Status.IN_PROGRESS)
        client, parser = scanners_registry.get(config)

        now_date = now()
        scan_list = client.get_scans(last_modification_date=config.last_scans_pull)
        scan_list = parser.get_scans_ids(scan_list)
        for scan_id in scan_list:
            LOGGER.info(F'Trying to download report form {config.name}')
            file = client.download_scan(scan_id)
            targets = copy.deepcopy(file)
            LOGGER.info(F'Retrieving discovered assets for {config.name}')
            discovered_assets = AssetDocument.get_assets_with_tag(tag=AssetStatus.DISCOVERED, config=config)
            LOGGER.info(F'Trying to parse scan file {scan_id}')
            vulns, scanned_hosts = parser.parse(file)
            LOGGER.info(F'File parsed: {scan_id}')
            LOGGER.info(F'Trying to parse targets from file {scan_id}')
            if hasattr(parser, "get_targets"):
                targets = parser.get_targets(targets)
            else:
                targets = client.get_targets(targets)
            LOGGER.info(F'Targets parsed: {scan_id}')
            if targets:
                LOGGER.info(F'Attempting to update discovered assets in {config.name}')
                AssetDocument.update_gone_discovered_assets(targets=targets, scanned_hosts=scanned_hosts,
                                                            discovered_assets=discovered_assets, config=config)
            LOGGER.info(F'Attempting to update vulns data in {config.name}')
            VulnerabilityDocument.create_or_update(vulns, scanned_hosts, config)
        config.last_scans_pull = now_date
        config.set_status(Config.Status.SUCCESS)
        config.save(update_fields=['last_scans_pull'])

    except Exception as e:
        config.set_status(status=Config.Status.ERROR, error_description=e)
        LOGGER.error(F'Error while loading vulnerability data {e}')
    finally:
        thread_pool_executor.wait_for_all()


def get_update_scans_workflow(config):
    vulnerability_index = DocumentRegistry.get_index_for_tenant(config.tenant, VulnerabilityDocument)
    asset_index = DocumentRegistry.get_index_for_tenant(config.tenant, AssetDocument)
    return (
        _update_scans.si(config_pk=config.id) |
        start_processing_per_tenant.si(vulnerability_index, asset_index)
    )


@shared_task(name='Update all scans')
def start_update_scans():
    for config in Config.objects.filter(enabled=True):
        config.set_status(status=Config.Status.PENDING)
        workflow = get_update_scans_workflow(config)
        start_workflow(workflow, config)
