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

import os

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand

from vmc.common.management.commands._common import wait_for_db_ready, wait_for_rabbit_ready


class Command(BaseCommand):
    help = 'Runs Admin Panel for VMC'

    def handle(self, *args, **options):
        self.stdout.write("Starting VMC Admin Panel")

        if wait_for_db_ready() and wait_for_rabbit_ready():
            call_command('migrate', *args, **options)

            if settings.DEBUG:
                call_command(
                    'loaddata',
                    *[Command._get_init_file_path()],
                    **options
                )
                call_command(
                    'runserver',
                    addrport='0.0.0.0:8080',
                    use_reloader=False,
                    use_ipv6=False,
                    use_threading=False
                )
            else:
                os.system("nginx")
                os.system("gunicorn vmc.config.wsgi:application --bind localhost:8001")

        else:
            self.stdout.write("Unable to start VMC Admin Panel")
            exit(1)

    @staticmethod
    def _get_init_file_path() -> str:
        import vmc
        return os.path.join(os.path.dirname(vmc.__file__), 'config', 'data', 'init.json')
