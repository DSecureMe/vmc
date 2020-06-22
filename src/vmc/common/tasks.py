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
import importlib
import logging
from celery.app import shared_task
from django.core.cache import cache
from vmc.config.celery import app

LOCK_EXPIRE = None
DEFAULT_RETRY_DELAY = 60 * 10
LOGGER = logging.getLogger(__name__)
ALL_TENANTS_KEY = 'workflow-all-tenants'


@app.task(bind=True, ignore_result=True, default_retry_delay=DEFAULT_RETRY_DELAY)
def __workflow(self, key: str, global_lock: bool):
    if not global_lock:
        all_tenants_lock = cache.get(ALL_TENANTS_KEY, None)

        if all_tenants_lock:
            LOGGER.info(F'Update for {ALL_TENANTS_KEY} already started, {key} postponed')
            raise self.retry()

    elif cache.keys('workflow-*'):
        LOGGER.info(F'Update for {ALL_TENANTS_KEY} postponed, other workflow in progress')
        raise self.retry()

    have_lock = cache.add(key, True, timeout=LOCK_EXPIRE)
    if not have_lock:
        LOGGER.info(F'Update for {key} already started, workflow postponed')
        raise self.retry()

    LOGGER.info(F'Update for {key} started')


@shared_task
def __release_lock(key: str):
    if cache.get(key, None):
        cache.delete(key)


@app.task(bind=True)
def __release_lock_error(key: str, module: str, model_name: str, config_pk: int):
    if cache.get(key, None):
        cache.delete(key)

    try:
        module = importlib.import_module(module)
        Config = getattr(module, model_name)
        config = Config.objects.get(pk=config_pk)
        config.set_status(status=Config.Status.ERROR, error_description=self.result.traceback)
    except Exception:
        LOGGER.error(F'Unable to set status for {key}')


def _get_key(config):
    return 'workflow-{}'.format(config.tenant.name if config and config.tenant else 'default')


def workflow_in_progress(config, global_lock=False):
    if not global_lock and cache.get(ALL_TENANTS_KEY, None):
        return True

    elif global_lock and cache.keys('workflow-*'):
        return True

    return cache.get(_get_key(config), False)


def get_task_error_handler(config=None):
    if config:
        return __release_lock_error.si(_get_key(config), config.__module__, config.__class__.__name__, config.pk)
    return __release_lock.si(_get_key(config))


def start_workflow(workflow, config=None, global_lock=False):
    key = _get_key(config)
    return __workflow.apply_async((key, global_lock),
                                  link=(workflow | __release_lock.si(key)),
                                  error_link=get_task_error_handler(config))

