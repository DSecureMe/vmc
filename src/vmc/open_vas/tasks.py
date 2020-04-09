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
 */
"""

from __future__ import absolute_import, unicode_literals

import logging

from celery import shared_task

from vmc.open_vas.models import Config
from vmc.common.tasks import memcache_lock
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.open_vas.clients import OpenVasClient, OpenVasClientError
from vmc.open_vas.parsers import GmpResultParser

LOGGER = logging.getLogger(__name__)


@shared_task
def update_result(config_pk, report_id):
    try:

        config = Config.objects.get(pk=config_pk)
        client = OpenVasClient(config)
        client.connect()
        result = client.get_report(report_id)
        parser = GmpResultParser(config)
        vulns, scanned_hosts = parser.parse(result)
        VulnerabilityDocument.create_or_update(vulns, scanned_hosts, config)

    except Exception as e:
        import traceback
        traceback.print_exc()
        LOGGER.error(F"Error while loading vulnerability data {e}")


def _update_data(config: Config):
    try:
        client = OpenVasClient(config)
        client.connect()

        for result_id in GmpResultParser.get_results_ids(client.get_reports()):
            update_result.delay(config_pk=config.pk, report_id=result_id)

    except OpenVasClientError as e:
        import traceback
        traceback.print_exc()
        LOGGER.error(F"Error while loading vulnerability data {e}")


@shared_task
def update_data(config_pk):
    config = Config.objects.get(pk=config_pk)
    lock_id = F"update-open-vas-vulnerabilities-loc-{config_pk}"
    with memcache_lock(lock_id, config) as acquired:
        if acquired:
            return _update_data(config)
    LOGGER.info(F"Vulnerability update for {config.name} is already being done by another worker")


@shared_task
def update():
    for config in Config.objects.all():
        update_data(config_pk=config.pk)

