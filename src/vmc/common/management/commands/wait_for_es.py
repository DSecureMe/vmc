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
from urllib.parse import urlparse

from django.core.management.base import BaseCommand

from vmc.common.management.commands._common import get_config, wait_for_port


class Command(BaseCommand):
    help = 'Wait for es'

    def handle(self, *args, **options):
        if not self.wait_for_es_ready():
            exit(1)

    @staticmethod
    def wait_for_es_ready():
        es_config = get_config('elasticsearch.hosts', ["http://elasticsearch:9200"])
        es_config = urlparse(es_config[0])
        return wait_for_port(es_config.port, es_config.hostname)
