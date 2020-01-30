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
from vmc.assets.documents import AssetDocument

from vmc.ralph.clients import RalphClient
from vmc.ralph.models import Config

from vmc.ralph.parsers import AssetsParser

LOGGER = logging.getLogger(__name__)


@shared_task
def update_assets(config_id: int):
    try:
        config = Config.objects.get(pk=config_id)
        client = RalphClient(config)
        parser = AssetsParser(config.name)
        LOGGER.info('Start loading data from Ralph: %s', config.name)
        assets = client.get_assets()
        assets = parser.parse(assets)
        AssetDocument.create_or_update(config.name, assets)
        LOGGER.info('Finish loading data from Ralph: %s', config.name)
    except Exception as ex:
        LOGGER.error('Error with loading data from Ralph: %s', ex)


@shared_task
def start_update_assets():
    for config in Config.objects.all().values_list('id', flat=True):
        update_assets.delay(config_id=config)
