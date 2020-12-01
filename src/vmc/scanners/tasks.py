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

import os

from pathlib import Path

from django.utils.timezone import now
from django.urls import reverse

from celery import shared_task
from zipfile import ZipFile

from vmc.config import settings
from vmc.elasticsearch.registries import DocumentRegistry
from vmc.common.utils import thread_pool_executor
from vmc.common.tasks import start_workflow
from vmc.scanners.models import Config, Scan
from vmc.scanners.registries import scanners_registry
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.assets.documents import AssetDocument, AssetStatus
from vmc.processing.tasks import start_processing_per_tenant

LOGGER = logging.getLogger(__name__)


@shared_task
def _update_scans(config_pk: int):
    LOGGER.debug(F'Starting update scans: {config_pk}')
    config = Config.objects.filter(pk=config_pk)

    if config.exists():
        config = config.first()
    else:
        LOGGER.error(F'Config: {config_pk} not exist!')
        return None

    try:
        config.set_status(Config.Status.IN_PROGRESS)
        manager = scanners_registry.get(config)
        client = manager.get_client()
        parser = manager.get_parser()
        now_date = now()

        LOGGER.info(F'Trying to download scan lists')
        scan_list = client.get_scans()
        scan_list = parser.get_scans_ids(scan_list)
        LOGGER.info(F'scan list downloaded')
        LOGGER.debug(F'Scan list: {scan_list}')

        for scan_id in scan_list:
            LOGGER.info(F'Trying to download report form {config.name}')

            file = client.download_scan(scan_id, client.ReportFormat.XML)

            path = _get_save_path(config)
            file_name = '{}-{}.zip'.format(config.scanner, now().strftime('%H-%M-%S'))
            full_file_path = Path(path) / file_name
            LOGGER.info(F"Saving file: {full_file_path}")
            thread_pool_executor.submit(save_scan, client, scan_id, file, full_file_path)
            saved_scan = Scan.objects.create(config=config, file=str(full_file_path))
            file_url = F"{getattr(settings, 'ABSOLUTE_URI', '')}{reverse('download_scan', args=[saved_scan.file_id])}"
            targets = copy.deepcopy(file)
            LOGGER.info(F'Retrieving discovered assets for {config.name}')
            discovered_assets = AssetDocument.get_assets_with_tag(tag=AssetStatus.DISCOVERED, config=config)
            LOGGER.info(F'Trying to parse scan file {scan_id}')
            vulns, scanned_hosts = parser.parse(file, file_url)

            LOGGER.info(F'File parsed: {scan_id}')
            LOGGER.info(F'Trying to parse targets from file {scan_id}')
            targets = parser.get_targets(targets)
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


def save_scan(client, scan_id, xml_file, full_file_path):
    try:
        pretty = client.download_scan(scan_id, client.ReportFormat.PRETTY)
        full_file_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(str(full_file_path), 'w') as zipfile:
            zipfile.writestr(F'report.{client.ReportFormat.XML}', xml_file.getvalue())
            zipfile.writestr(F'report.{client.ReportFormat.PRETTY}', pretty.read())
        LOGGER.info(F'File {str(full_file_path)} saved')
    except (MemoryError, IOError, PermissionError, TimeoutError, FileExistsError) as e:
        LOGGER.error(F"There were exception during saving file: {full_file_path}. Exception:\n{e}")


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


def _get_save_path(config):
    if hasattr(settings, 'BACKUP_ROOT'):
        current_date = now()
        return os.path.join(
            getattr(settings, 'BACKUP_ROOT'),
            'scans',
            str(current_date.year),
            str(current_date.month),
            str(current_date.day),
            F'{config.id}-{config.tenant.slug_name}' if config.tenant else F'{config.id}'
        )
    return None
