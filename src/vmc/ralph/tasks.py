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

from vmc.ralph.api import Ralph
from vmc.ralph.models import Config

from vmc.ralph.factories import AssetFactory

LOGGER = logging.getLogger(__name__)


@shared_task
def load_all_assets():
    LOGGER.info('Start loading data from ralph')
    try:
        ralph_api = Ralph(config=Config.objects.first())
        all_assets = ralph_api.get_all_assets()

        for asset in all_assets:
            AssetFactory.process(asset)
    except Exception as ex:
        LOGGER.error(ex)
    LOGGER.info('Finish loading data from ralph')
