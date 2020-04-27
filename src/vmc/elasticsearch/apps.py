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
from celery.schedules import crontab
from django.apps import AppConfig
from django.conf import settings

from vmc.config.celery import app
from elasticsearch_dsl.connections import connections


class ElasticSearchConfig(AppConfig):
    name = 'vmc.elasticsearch'
    verbose_name = 'ElasticSearch'

    def ready(self):
        self.module.autodiscover()
        if getattr(settings, 'ELASTICSEARCH_DSL', None):
            connections.configure(**settings.ELASTICSEARCH_DSL)

            app.conf.beat_schedule = {
                'create snapshot every day at midnight': {
                    'task': 'vmc.elasticsearch.tasks.snapshot',
                    'schedule': crontab(hour=0, minute=0),
                    'args': ('dayli', )
                },
                'create snapshot every first day of month at midnight': {
                    'task': 'vmc.elasticsearch.tasks.snapshot',
                    'schedule': crontab(hour=0, minute=0, day_of_month=1),
                    'args': ('monthly', )
                },
            }
