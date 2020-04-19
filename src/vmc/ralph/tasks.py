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
from celery import shared_task, group

from vmc.common.tasks import memcache_lock
from vmc.assets.documents import AssetDocument
from vmc.processing.tasks import start_processing

from vmc.ralph.clients import RalphClient
from vmc.ralph.models import Config

from vmc.ralph.parsers import AssetsParser, OwnerParser

LOGGER = logging.getLogger(__name__)


def _update(config: Config):
    try:
        client = RalphClient(config)
        parser = AssetsParser(config)
        LOGGER.info(F'Start loading data from Ralph: {config.name}')
        users = client.get_users()
        users = OwnerParser.parse(users)
        assets = client.get_assets()
        assets = parser.parse(assets, users)
        AssetDocument.create_or_update(assets, config)
        LOGGER.info(F'Finish loading data from Ralph: {config.name}')
    except Exception as ex:
        import traceback
        traceback.print_exc()
        LOGGER.error(F'Error with loading data from Ralph: {ex}')


@shared_task
def update_assets(config_id: int):
    config = Config.objects.get(pk=config_id)
    lock_id = F'update-assets-lock-{config.id}'
    with memcache_lock(lock_id, config.id) as acquired:
        if acquired:
            return _update(config)
    LOGGER.info(F'Update assets for {config.name} is already being imported by another worker')


@shared_task
def start_update_assets():
    configs = Config.objects.all().values_list('id', flat=True)
    (
        group(update_assets.si(config_id=config) for config in configs) |
        start_processing.si()
    )()
