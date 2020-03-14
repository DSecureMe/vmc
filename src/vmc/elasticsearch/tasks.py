
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
import logging

from celery import shared_task

from elasticsearch.helpers import bulk
from elasticsearch_dsl.connections import get_connection
from django.utils.timezone import now

from vmc.elasticsearch.registries import registry, SnapShotMode
from vmc.elasticsearch import Search

LOGGER = logging.getLogger(__name__)

STEP = 1000
START = 0


@shared_task
def snapshot(name: str) -> None:
    for index in registry.get_documents():
        if index.split('.')[-1] not in SnapShotMode.values():
            _snapshot_documents.delay(name=name, index=index)


@shared_task
def _snapshot_documents(name: str, index: str) -> None:
    docs = []
    LOGGER.info('Creating snapshot for %s %s', index, name)
    total = Search(index=index).count()
    paging = [(START if i == START else i + 1, i + STEP) for i in range(START, total, STEP)]
    for st, en in paging:
        for current in Search(index=index)[st:en]:
            current.snapshot_date = now()
            docs.append(current.to_dict())

        if docs:
            bulk(get_connection(), docs, refresh=True, index='{}.{}'.format(index, name))
    LOGGER.info('Snapshot for %s %s done', index, name)
