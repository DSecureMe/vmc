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

from vmc.webhook.thehive.models import Task
from vmc.elasticsearch.registries import registry
from vmc.elasticsearch.models import Tenant
from vmc.vulnerabilities.documents import VulnerabilityDocument
from vmc.webhook.models import TheHive4LogConverter


LOGGER = logging.getLogger(__name__)


@shared_task
def process_task_log(event):
    try:
        LOGGER.debug(event)
        if 'object' in event:
            message = event['object']['message']
            task_id = event['object']['case_task']['id']
            tasks = Task.objects.filter(task_id=task_id)
            converter = TheHive4LogConverter.objects.filter(log_message=message)
            LOGGER.debug(F'Task id {task_id}, found {tasks}')
            LOGGER.debug(F'Converter found: {converter}')
            if tasks.exists() and converter.exists():
                task = tasks.first()
                tag = converter.first().tag
                try:
                    tenant = Tenant.objects.get(name=task.tenant)
                    index = registry.get_index_for_tenant(tenant, VulnerabilityDocument)
                except Tenant.DoesNotExist:
                    index = VulnerabilityDocument.Index.name

                doc = VulnerabilityDocument.get(task.document_id, index=index)

                LOGGER.debug(F'Documents found')

                if hasattr(doc, 'tags'):
                    if tag not in doc.tags:
                        doc.tags.append(tag)
                        LOGGER.debug(F'Saved')
                        doc.save()
                else:
                    doc.tags = [tag]
                    LOGGER.debug(F'Saved')
                    doc.save()

    except Exception as ex:
        LOGGER.error(ex)
