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

import logging

from celery import shared_task

from vmc.vulnerabilities.documents import VulnerabilityDocument

from vmc.elasticsearch.registries import DocumentRegistry
from vmc.common.utils import thread_pool_executor
from vmc.common.tasks import start_workflow
from vmc.assets.documents import AssetDocument
from vmc.processing.tasks import start_processing_per_tenant

from vmc.ralph.clients import RalphClient
from vmc.ralph.models import Config

from vmc.ralph.parsers import AssetsParser, OwnerParser

LOGGER = logging.getLogger(__name__)


@shared_task
def _update_assets(config_id: int):
    config = Config.objects.filter(pk=config_id)

    if config.exists():
        config = config.first()

        try:
            config.set_status(Config.Status.IN_PROGRESS)
            client = RalphClient(config)
            parser = AssetsParser(config)
            LOGGER.info(F'Start loading data from Ralph: {config.name}')
            users = client.get_users()
            users = OwnerParser.parse(users)

            assets = client.get_data_center_assets()
            assets = parser.parse(assets, users)
            AssetDocument.create_or_update(assets, config)
            LOGGER.info(F'Finish loading data center assets from Ralph: {config.name}')

            assets = client.get_virtual_assets()
            assets = parser.parse(assets, users)
            AssetDocument.create_or_update(assets, config)
            LOGGER.info(F'Finish loading virtual assets from Ralph: {config.name}')
            LOGGER.info(F'Finish loading data from Ralph: {config.name}')

            config.set_status(Config.Status.SUCCESS)
        except Exception as ex:
            LOGGER.error(F'Error with loading data from Ralph: {ex}')
            config.set_status(status=Config.Status.ERROR, error_description=ex)
        finally:
            thread_pool_executor.wait_for_all()


def get_update_assets_workflow(config):
    vulnerability_index = DocumentRegistry.get_index_for_tenant(config.tenant, VulnerabilityDocument)
    asset_index = DocumentRegistry.get_index_for_tenant(config.tenant, AssetDocument)
    return (
        _update_assets.si(config_id=config.pk) |
        start_processing_per_tenant.si(vulnerability_index, asset_index)
    )


@shared_task(name='Update all assets')
def start_update_assets():
    for config in Config.objects.filter(enabled=True):
        config.set_status(status=Config.Status.PENDING)
        workflow = get_update_assets_workflow(config)
        start_workflow(workflow, config)

