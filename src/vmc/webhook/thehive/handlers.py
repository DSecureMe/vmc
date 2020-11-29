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

from vmc.common.utils import thread_pool_executor
from vmc.webhook.thehive.models import Task
from vmc.webhook.thehive.client import TheHiveClient
from vmc.webhook.thehive.conventer import TaskProcessor, CaseManager
from vmc.webhook.thehive.tasks import process_task_log
from vmc.webhook.models import TheHive4


LOGGER = logging.getLogger(__name__)


def alert_create(event):
    try:
        if 'vmc\\vulnerability' == event['details']['type']:
            alert_id = str(event['details']['_id']).replace(' ', '')
            if not Task.objects.filter(alert_id=alert_id).exists():
                task = Task.objects.create(alert_id=alert_id)
                thread_pool_executor.submit(_process_tasks, task)
                LOGGER.info(F'alert saved {alert_id}')
            else:
                LOGGER.info(F'alert already exists {alert_id}')
    except Exception as ex:
        LOGGER.error(ex)


def _process_tasks(new_task):
    config = TheHive4.objects.first()
    hive_client = TheHiveClient(config.get_url(), config.token)

    task_processor = TaskProcessor(hive_client)
    task_processor.process(new_task)

    case_manager = CaseManager(hive_client)

    if new_task.title:
        case = case_manager.get_or_create_case(new_task.scan_url, new_task.source, new_task.tenant)
        case_manager.merge_alert_to_case(case, new_task)
    else:
        LOGGER.debug(F'Task {new_task.id} with empty title')
    case_manager.update_cases_desc()


def case_task_log(event):
    process_task_log.delay(event)


handlers_map = {
    'AlertCreate': alert_create,
    'CaseTaskLogCreate': case_task_log
}