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

from django.core.management.base import BaseCommand

from vmc.common.management.commands._common import get_config, wait_for_socket, wait_for_port


class Command(BaseCommand):
    help = 'Wait for db'

    def handle(self, *args, **options):
        if not self.wait_for_db_ready():
            exit(1)

    @staticmethod
    def wait_for_db_ready():
        db_socket = get_config('database.unix_socket', '')
        if db_socket:
            return wait_for_socket(db_socket)
        return wait_for_port(
            get_config('database.port', 5432),
            get_config('database.host', 'localhost')
        )